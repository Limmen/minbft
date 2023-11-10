from typing import List, Dict, Tuple
import grpc
import logging
import socket
import netifaces
import numpy as np
from concurrent import futures
import minbft_client_manager_pb2_grpc
import minbft_client_manager_pb2
import minbft_manager_pb2
import minbft_manager_pb2_grpc
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from crypto_util import CryptoUtil
import csle_collector.constants.constants as constants
from operation_type import OperationType
from view_change_trigger_thread import ViewChangeTriggerThread


class MinbftManagerServicer(minbft_manager_pb2_grpc.MinbftManagerServicer):
    """
    gRPC server for running the MinBFT consensus protocol
    """

    def __init__(self, port: int) -> None:
        """
        Initializes the server

        :param port: the port that the server listens to
        """
        logging.basicConfig(filename=f"{constants.LOG_FILES.MINBFT_MANAGER_LOG_DIR}"
                                     f"{constants.LOG_FILES.MINBFT_MANAGER_LOG_FILE}", level=logging.INFO)
        self.port: int = port
        self.hostname: str = socket.gethostname()
        self.ip: str = ""
        try:
            self.ip = netifaces.ifaddresses(constants.INTERFACES.ETH0)[netifaces.AF_INET][0][constants.INTERFACES.ADDR]
        except Exception:
            self.ip = socket.gethostbyname(self.hostname)
        self.id: int = 0
        logging.info(f"Setting up the Minbft manager, hostname: {self.hostname} ip: {self.ip}")
        self.compromised: bool = False
        self.crashed: bool = False
        self.unique_identifier: int = 0
        private_rsa_key, public_rsa_key = CryptoUtil.generate_rsa_keys(key_len=1024)
        self.private_rsa_key: RsaKey = private_rsa_key
        self.public_rsa_key: RsaKey = public_rsa_key
        self.node_ips: List[str] = []
        self.node_ports: List[int] = []
        self.node_ids: List[int] = []
        self.node_public_keys: List[bytes] = []
        self.clients_public_keys: List[bytes] = []
        self.client_ips: List[str] = []
        self.client_ports: List[int] = []
        self.client_ids: List[int] = []
        self.state = -1
        self.leader_timeout_seconds: int = 10
        self.leader_ip: str = ""
        self.leader_port: int = -1
        self.leader_id: int = -1
        self.view_id: int = 0
        self.prepare_messages_log: Dict[Tuple[str, int, int, int, int], minbft_manager_pb2.PrepareMsg] = {}
        self.commit_messages_log: Dict[Tuple[str, int, int, int, int], minbft_manager_pb2.CommitMsg] = {}
        self.received_commit_messages_log: Dict[Tuple[str, int, int, int, int], List[minbft_manager_pb2.CommitMsg]] = {}
        self.received_prepare_messages_log: Dict[Tuple[str, int, int, int, int], minbft_manager_pb2.PrepareMsg] = {}
        self.V_req: Dict[Tuple[str, int, int], int] = {}
        self.V_acc: Dict[Tuple[str, int, int], int] = {}
        self.commits: Dict[Tuple[str, int, int, int], Tuple[minbft_manager_pb2.CommitMsg, int]] = {}
        self.commit_log: List[Tuple[str, int, int, int, int, int]] = []
        self.fault_threshold: int = 1
        self.checkpoint_period = 1
        self.received_checkpoint_messages_log: Dict[Tuple[int, int], List[minbft_manager_pb2.CheckpointMsg]] = {}
        self.checkpoint_messages_log: Dict[Tuple[int, int], minbft_manager_pb2.CheckpointMsg] = {}
        self.low_watermark = -1
        self.maximum_log_size = 1000
        self.view_change_trigger_threads: Dict[Tuple[str, int, int, int]] = {}
        self.checkpoint_state = -1
        self.checkpoint_certificate = []
        self.new_view_certificate = []
        self.received_request_view_change_messages: (
            Dict)[int, List[minbft_manager_pb2.RequestViewChangeMsg]] = {}
        self.received_view_change_message_log: Dict[int, List[minbft_manager_pb2.ViewChangeMsg]] = {}
        self.view_change_message_log: Dict[int, minbft_manager_pb2.ViewChangeMsg] = {}
        self.new_view_message_log: Dict[int, minbft_manager_pb2.NewViewMsg] = {}
        self.pending_view_change = False
        self.pending_view_change = False

    def cleanup_logs(self, checkpoint_unique_identifier: int) -> None:
        """
        Cleans up the logs after a checkpoint

        :param checkpoint_unique_identifier: the UI of the checkpoint
        :return: None
        """
        prepare_messages_log = {}
        commit_messages_log = {}
        received_commit_messages_log = {}
        received_prepare_messages_log = {}
        commits = {}
        commit_log = []
        for k, v in self.prepare_messages_log.items():
            if v.uniqueIdentifier.uniqueIdentifier >= checkpoint_unique_identifier:
                prepare_messages_log[k] = v
        for k, v in self.commit_messages_log.items():
            if v.leaderUniqueIdentifier.uniqueIdentifier >= checkpoint_unique_identifier:
                commit_messages_log[k] = v
        for k, v in self.received_commit_messages_log.items():
            v_prime = []
            for i in range(len(v)):
                if v[i].leaderUniqueIdentifier.uniqueIdentifier >= checkpoint_unique_identifier:
                    v_prime.append(v[i])
            if len(v_prime) > 0:
                received_commit_messages_log[k] = v_prime
        for k, v in self.received_prepare_messages_log.items():
            if v.uniqueIdentifier.uniqueIdentifier >= checkpoint_unique_identifier:
                received_prepare_messages_log[k] = v
        for k, v in self.commits.items():
            if v[0].leaderUniqueIdentifier.uniqueIdentifier >= checkpoint_unique_identifier:
                commits[k] = v
        for i in range(len(self.commit_log)):
            if self.commit_log[i][4] >= checkpoint_unique_identifier:
                commit_log.append(self.commit_log[i])
        self.prepare_messages_log = prepare_messages_log
        self.commit_messages_log = commit_messages_log
        self.received_commit_messages_log = received_commit_messages_log
        self.received_prepare_messages_log = received_prepare_messages_log
        self.commits = commits
        self.commit_log = commit_log
        self.received_checkpoint_messages_log = {}
        self.received_request_view_change_messages = {}
        self.view_change_message_log = {}
        self.new_view_message_log = {}
        self.new_view_certificate = []
        self.checkpoint_messages_log = {}

    def initiate_checkpoint(self) -> None:
        """
        Initiates a checkpoint of the latest commit

        :return: None
        """
        key = (self.commit_log[-1][0], self.commit_log[-1][1], self.commit_log[-1][2], self.commit_log[-1][3])
        commit = self.commits[key][0]
        # Check if we have already broadcasted the checkpoint
        if (commit.leaderUniqueIdentifier.uniqueIdentifier, self.view_id) in self.checkpoint_messages_log:
            return
        checkpoint_id = f"{self.ip}-{self.port}-{self.id}-{commit.leaderUniqueIdentifier.uniqueIdentifier}-checkpoint"
        usig_certificate: minbft_manager_pb2.USIGCertificateDTO = self.local_create_UI(request_message=checkpoint_id)
        self.V_acc[(self.ip, self.port, self.id)] = usig_certificate.uniqueIdentifier
        checkpoint_msg = minbft_manager_pb2.CheckpointMsg(
            viewId=self.view_id, nodeIp=self.ip, nodePort=self.port, nodeId=self.id,
            checkpointUniqueIdentifier=commit.leaderUniqueIdentifier, nodeUniqueIdentifier=usig_certificate,
            state=self.state, leaderIp=commit.leaderIp, leaderPort=commit.leaderPort, leaderId=commit.leaderId
        )
        self.checkpoint_messages_log[(commit.leaderUniqueIdentifier.uniqueIdentifier, self.view_id)] = checkpoint_msg
        self.broadcast_checkpoint(checkpoint_msg=checkpoint_msg)
        self.add_received_checkpoint_to_message_queue(checkpoint=checkpoint_msg)
        if self.has_a_checkpoint_quorum_been_reached(checkpoint=checkpoint_msg):
            self.accept_checkpoint(checkpoint_msg=checkpoint_msg)

    def broadcast_checkpoint(self, checkpoint_msg: minbft_manager_pb2.CheckpointMsg) -> None:
        """
        Broadcasts a <Checkpoint> to all nodes

        :param checkpoint_msg: the checkpoint msg to broadcast
        :return: None
        """
        for i, node_ip in enumerate(self.node_ips):
            if node_ip != self.ip or self.node_ports[i] != self.port or self.node_ids[i] != self.id:
                try:
                    with grpc.insecure_channel(f"{node_ip}:{self.node_ports[i]}") as channel:
                        stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                        stub.checkpoint(checkpoint_msg)
                except:
                    pass

    def broadcast_request_view_change(self, request_view_change_msg: minbft_manager_pb2.RequestViewChangeMsg) -> None:
        """
        Broadcasts a <Req-View-Change> to all nodes

        :param request_view_change_msg: the request view change msg to broadcast
        :return: None
        """
        for i, node_ip in enumerate(self.node_ips):
            if node_ip != self.ip or self.node_ports[i] != self.port or self.node_ids[i] != self.id:
                try:
                    with grpc.insecure_channel(f"{node_ip}:{self.node_ports[i]}") as channel:
                        stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                        stub.requestViewChange(request_view_change_msg)
                except:
                    pass

    def broadcast_view_change(self, view_change_msg: minbft_manager_pb2.ViewChangeMsg) -> None:
        """
        Broadcasts a <View-Change> to all nodes

        :param view_change_msg: the view change msg to broadcast
        :return: None
        """
        self.view_change_message_log[view_change_msg.viewId] = view_change_msg
        for i, node_ip in enumerate(self.node_ips):
            if node_ip != self.ip or self.node_ports[i] != self.port or self.node_ids[i] != self.id:
                try:
                    with grpc.insecure_channel(f"{node_ip}:{self.node_ports[i]}") as channel:
                        stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                        stub.viewChange(view_change_msg)
                except:
                    pass

    def broadcast_new_view(self, new_view_msg: minbft_manager_pb2.NewViewMsg) -> None:
        """
        Broadcasts a <New-View> to all nodes

        :param new_view_msg: the new view msg to broadcast
        :return: None
        """
        self.pending_view_change = False
        self.new_view_message_log[new_view_msg.viewId] = new_view_msg
        self.received_view_change_message_log[new_view_msg.viewId] = []
        for i, node_ip in enumerate(self.node_ips):
            if node_ip != self.ip or self.node_ports[i] != self.port or self.node_ids[i] != self.id:
                try:
                    with grpc.insecure_channel(f"{node_ip}:{self.node_ports[i]}") as channel:
                        stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                        stub.newView(new_view_msg)
                except:
                    pass

    def send_prepare(self, request: minbft_manager_pb2.ServiceRequestMsg) -> bool:
        """
        Send prepare for a given service request

        :param request: the request to prepare for
        :return: True if the prepare was sent, otherwise False
        """
        current_sequence_number = self.V_req[(request.clientIp, request.clientPort, request.clientId)]
        key = (request.clientIp, request.clientPort, request.clientId, current_sequence_number)
        if request.sequenceNumber > current_sequence_number and (key in self.commits or current_sequence_number == -1):
            # New sequence number and the previous one is committed.
            if self.am_i_leader():
                message = f"{request.clientIp}-{request.clientPort}-{request.sequenceNumber}-" \
                          f"{request.operationType}-{request.operationData}"
                logging.info(f"Leader: ({self.id}, {self.ip}, {self.port}) "
                             f"received request: {request.sequenceNumber} from client: {request.clientId}, "
                             f"UI:{self.unique_identifier + 1}")
                usig_certificate: minbft_manager_pb2.USIGCertificateDTO = self.local_create_UI(
                    request_message=message)
                self.V_acc[(self.ip, self.port, self.id)] = usig_certificate.uniqueIdentifier
                self.broadcast_prepare(request=request, usig_certificate=usig_certificate)
                return True
        elif request.sequenceNumber == current_sequence_number and key not in self.commits:
            # Currently processing this sequence number, resend the prepare
            if self.am_i_leader():
                key = (request.clientIp, request.clientPort, request.clientId, request.sequenceNumber, self.view_id)
                usig_certificate = self.prepare_messages_log[key].uniqueIdentifier
                self.broadcast_prepare(request=request, usig_certificate=usig_certificate)
                return True
        elif request.sequenceNumber > current_sequence_number and key not in self.commits:
            # Currently processing an earlier sequence number, which means that we should ignore this one
            return False
        elif (request.sequenceNumber < current_sequence_number or
              (request.sequenceNumber == current_sequence_number and key in self.commits)):
            # Request is already committed, reply with cached result
            self.reply_to_client(client_request=request)
            return False
        return False

    def is_ui_sequential(self, unique_identifier: minbft_manager_pb2.USIGCertificateDTO,
                         node_ip: str, node_port: int, node_id: int) -> bool:
        """
        Verifies that a UI propose by a node is sequential

        :param unique_identifier: the unique identifier proposed by the node
        :param node_ip: the node's ip
        :param node_port: the node's port
        :param node_id: the node's id
        :return: True if it is sequentially consistent, otherwise False
        """
        key = (node_ip, node_port, node_id)
        if key not in self.V_acc:
            return True
        if self.V_acc[key] == -1:
            return True
        if self.V_acc[key] == unique_identifier.uniqueIdentifier:
            return True
        if (self.V_acc[key] + 1) == unique_identifier.uniqueIdentifier:
            return True
        return False

    def is_prepare_message_valid(self, prepare_msg: minbft_manager_pb2.PrepareMsg) -> bool:
        """
        Utility method for verifying a prepare message

        :param prepare_msg: the prepare message to verify
        :return: True if it is verified, otherwise False
        """
        if prepare_msg.viewId != self.view_id:
            return False
        if prepare_msg.leaderIp != self.leader_ip:
            return False
        if prepare_msg.leaderPort != self.leader_port:
            return False
        if prepare_msg.leaderId != self.leader_id:
            return False
        return True

    def is_commit_message_valid(self, commit_msg: minbft_manager_pb2.CommitMsg) -> bool:
        """
        Utility method for verifying a commit message

        :param commit_msg: the prepare message to verify
        :return: True if it is verified, otherwise False
        """
        if commit_msg.viewId != self.view_id:
            return False
        if commit_msg.leaderIp != self.leader_ip:
            return False
        if commit_msg.leaderPort != self.leader_port:
            return False
        if commit_msg.leaderId != self.leader_id:
            return False
        return True

    def is_client_request_valid(self, client_reqest: minbft_manager_pb2.ServiceRequestMsg) -> bool:
        """
        Utility method for verifying a client request

        :param client_reqest: the client request to verify
        :return: True if it is verified, otherwise False
        """
        if client_reqest.clientIp not in self.client_ips:
            return False
        message = (f"{client_reqest.clientIp}-{client_reqest.clientPort}-{client_reqest.clientId}-"
                   f"{client_reqest.sequenceNumber}-"
                   f"{client_reqest.operationType}-{client_reqest.operationData}")
        client_public_key_pem = self.clients_public_keys[self.client_ips.index(client_reqest.clientIp)]
        client_public_key: RsaKey = RSA.import_key(client_public_key_pem)
        valid = CryptoUtil.verify_signature(message=message, signature=client_reqest.signature,
                                            rsa_public_key=client_public_key)
        if not valid:
            return False
        return True

    def add_received_commit_to_message_queue(self, commit: minbft_manager_pb2.CommitMsg) -> None:
        """
        Adds a given commit message to the message queue

        :param commit: the commit to add
        :return: None
        """
        key = (commit.message.clientIp, commit.message.clientPort, commit.message.clientId,
               commit.message.sequenceNumber, commit.viewId)
        if key not in self.received_commit_messages_log:
            self.received_commit_messages_log[key] = [commit]
        else:
            self.received_commit_messages_log[key].append(commit)

    def add_received_prepare_to_message_queue(self, prepare: minbft_manager_pb2.PrepareMsg) -> None:
        """
        Adds a given prepare message to the message queue

        :param commit: the commit to add
        :return: None
        """
        key = (prepare.message.clientIp, prepare.message.clientPort, prepare.message.clientId,
               prepare.message.sequenceNumber, prepare.viewId)
        self.received_prepare_messages_log[key] = prepare

    def add_commit_to_message_queue(self, commit: minbft_manager_pb2.CommitMsg) -> None:
        """
        Adds a given commit message to the message queue

        :param commit: the commit to add
        :return: None
        """
        key = (commit.message.clientIp, commit.message.clientPort, commit.message.clientId,
               commit.message.sequenceNumber, commit.viewId)
        self.commit_messages_log[key] = commit

    def add_prepare_to_message_queue(self, prepare: minbft_manager_pb2.PrepareMsg) -> None:
        """
        Adds a given prepare message to the message queue

        :param commit: the commit to add
        :return: None
        """
        key = (prepare.message.clientIp, prepare.message.clientPort, prepare.message.clientId,
               prepare.message.sequenceNumber, prepare.viewId)
        self.prepare_messages_log[key] = prepare

    def add_received_checkpoint_to_message_queue(self, checkpoint: minbft_manager_pb2.CheckpointMsg) -> None:
        """
        Adds a given checkpoint message to the message queue

        :param checkpoint: the commit to add
        :return: None
        """
        key = (checkpoint.checkpointUniqueIdentifier.uniqueIdentifier, checkpoint.viewId)
        if key not in self.received_checkpoint_messages_log:
            self.received_checkpoint_messages_log[key] = [checkpoint]
        else:
            self.received_checkpoint_messages_log[key].append(checkpoint)

    def broadcast_prepare(self, request: minbft_manager_pb2.ServiceRequestMsg,
                          usig_certificate: minbft_manager_pb2.USIGCertificateDTO) -> None:
        """
        Broadcasts a <Prepare> to commit a given service request to all nodes

        :param request: the service request
        :param usig_certificate: the leader's certificate
        :return: None
        """
        for i, node_ip in enumerate(self.node_ips):
            if node_ip != self.ip or self.node_ports[i] != self.port or self.node_ids[i] != self.id:
                prepare_msg = minbft_manager_pb2.PrepareMsg(
                    viewId=self.view_id,
                    leaderIp=self.ip,
                    leaderPort=self.port,
                    leaderId=self.id,
                    message=request,
                    uniqueIdentifier=usig_certificate
                )
                self.add_prepare_to_message_queue(prepare=prepare_msg)
                try:
                    with grpc.insecure_channel(f"{node_ip}:{self.node_ports[i]}") as channel:
                        stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                        stub.prepare(prepare_msg)
                except:
                    pass

    def broadcast_commit(self, prepare_msg: minbft_manager_pb2.PrepareMsg,
                         usig_certificate: minbft_manager_pb2.USIGCertificateDTO) -> None:
        """
        Broadcasts a <Commit> message for a given prepare message

        :param prepare_msg: the prepare message
        :param usig_certificate: the follower's certificate
        :return: None
        """
        key = (prepare_msg.message.clientIp, prepare_msg.message.clientPort, prepare_msg.message.clientId)
        self.V_req[key] = prepare_msg.message.sequenceNumber
        for i, node_ip in enumerate(self.node_ips):
            if node_ip != self.ip or self.node_ports[i] != self.port or self.node_ids[i] != self.id:
                commit_msg = minbft_manager_pb2.CommitMsg(
                    viewId=self.view_id,
                    leaderIp=prepare_msg.leaderIp,
                    leaderPort=prepare_msg.leaderPort,
                    leaderId=prepare_msg.leaderId,
                    followerIp=self.ip,
                    followerPort=self.port,
                    followerId=self.id,
                    message=prepare_msg.message,
                    leaderUniqueIdentifier=prepare_msg.uniqueIdentifier,
                    followerUniqueIdentifier=usig_certificate
                )
                self.add_commit_to_message_queue(commit=commit_msg)
                try:
                    with grpc.insecure_channel(f"{node_ip}:{self.node_ports[i]}") as channel:
                        stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                        stub.commit(commit_msg)
                except:
                    pass

    def local_create_UI(self, request_message: str) -> minbft_manager_pb2.USIGCertificateDTO:
        """
        Utility method for creating a new USIG certificate for a given message

        :param request_message: the message to create the certificate for
        :return: the certificate
        """
        self.unique_identifier = self.unique_identifier + 1
        message = f"{request_message}-{self.ip}-{self.port}-{self.id}-{self.unique_identifier}"
        signature = CryptoUtil.sign_message_rsa(rsa_private_key=self.private_rsa_key, message=message)
        usig_certificate = minbft_manager_pb2.USIGCertificateDTO(
            uniqueIdentifier=self.unique_identifier,
            signature=signature,
            message=message,
            nodeIp=self.ip,
            nodePort=self.port,
            nodeId=self.id
        )
        return usig_certificate

    def getNodes(self, request: minbft_manager_pb2.GetNodesMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.NodesDTO:
        """
        Gets the nodes configuration

        :param request: the gRPC request
        :param context: the gRPC context
        :return: A nodesDTO with the node IPs, ports, and public keys
        """
        nodes_dto = minbft_manager_pb2.NodesDTO(nodeIps=self.node_ips, nodePorts=self.node_ports,
                                                publicKeys=self.node_public_keys,
                                                leaderTimeoutSeconds=self.leader_timeout_seconds,
                                                faultThreshold=self.fault_threshold)
        return nodes_dto

    def getPublicRSAKey(self, request: minbft_manager_pb2.GetPublicRSAKeyMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.PublicRSAKeyDTO:
        """
        Gets the public RSA key of the node

        :param request: the gRPC request
        :param context: the gRPC context
        :return: a PublicRSAKeyDTO with the key in PEM bytes
        """
        key_dto = minbft_manager_pb2.PublicRSAKeyDTO(key=self.public_rsa_key.export_key(format="PEM"))
        return key_dto

    def setNodes(self, request: minbft_manager_pb2.NodesDTO, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.NodesDTO:
        """
        Sets the nodes configuration

        :param request: the gRPC request
        :param context: the gRPC context
        :return: the updated nodes configuration (a NodesDTO)
        """
        self.node_ips = list(request.nodeIps)
        self.node_ports = list(request.nodePorts)
        self.node_public_keys = list(request.publicKeys)
        self.node_ids = list(request.nodeIds)
        self.prepare_messages_log = {}
        self.commit_messages_log = {}
        self.received_prepare_messages_log = {}
        self.received_commit_messages_log = {}
        self.leader_timeout_seconds = request.leaderTimeoutSeconds
        self.fault_threshold = request.faultThreshold
        self.checkpoint_period = request.checkpointPeriod
        self.view_id = 0
        leader_idx = self.view_id % len(self.node_ips)
        self.leader_id = self.node_ids[leader_idx]
        self.leader_ip = self.node_ips[leader_idx]
        self.leader_port = self.node_ports[leader_idx]
        my_idx = max([self.node_ips.index(self.ip), self.node_ports.index(self.port)])
        self.id = self.node_ids[my_idx]
        for i in range(len(self.node_ips)):
            self.V_acc[(self.node_ips[i], self.node_ports[i], self.node_ids[i])] = -1
        logging.info(f"Updated nodes configurations, ips: {self.node_ips}, ports: {self.node_ports}, "
                     f"ids: {self.node_ids}, "
                     f"leader timeout: {self.leader_timeout_seconds}, "
                     f"leader: {self.leader_ip}, view id: {self.view_id}, faultThreshold: {self.fault_threshold}, "
                     f"node id:{self.id}, checkpoint period: {self.checkpoint_period}")
        return request

    def am_i_leader(self) -> bool:
        """
        :return: True if the node is leader, false otherwise
        """
        return self.ip == self.leader_ip and self.port == self.leader_port and self.id == self.leader_id

    def has_a_quorum_been_reached(self, commit: minbft_manager_pb2.CommitMsg) -> bool:
        """
        Checks if a quorum has been reached for a given commit

        :param commit: to commit to check
        :return: True if a quorum of commits have been reached and False otherwise
        """
        key = (commit.message.clientIp, commit.message.clientPort, commit.message.clientId,
               commit.message.sequenceNumber, commit.viewId)
        if len(self.received_commit_messages_log[key]) >= (self.fault_threshold):
            return True
        return False

    def has_a_request_view_change_quorum_been_reached(
            self, request_view_change_msg: minbft_manager_pb2.RequestViewChangeMsg) -> bool:
        """
        Checks if a quorum has been reached for a given request for view change

        :param request_view_change_msg: the view change to check
        :return: True if a quorum of request view change messages have been reached and False otherwise
        """
        if (len(self.received_request_view_change_messages[request_view_change_msg.newViewId])
                >= (self.fault_threshold)):
            return True
        return False

    def has_a_view_change_quorum_been_reached(self, view_change_msg: minbft_manager_pb2.ViewChangeMsg) -> bool:
        """
        Checks if a quorum has been reached for a given view change

        :param view_change_msg: the view change to check
        :return: True if a quorum of view change messages have been reached and False otherwise
        """
        if len(self.received_view_change_message_log[view_change_msg.viewId]) >= (self.fault_threshold):
            return True
        return False

    def has_a_checkpoint_quorum_been_reached(self, checkpoint: minbft_manager_pb2.CheckpointMsg) -> bool:
        """
        Checks if a quorum has been reached for a given checkpoint

        :param checkpoint: to checkpoint to check
        :return: True if a quorum of checkpoints has been reached, False otherwise
        """
        key = (checkpoint.checkpointUniqueIdentifier.uniqueIdentifier, checkpoint.viewId)
        if key not in self.checkpoint_messages_log:
            return False
        if key not in self.received_checkpoint_messages_log:
            return False
        if len(self.received_checkpoint_messages_log[key]) >= self.fault_threshold:
            states = list(map(lambda x: x.state, self.received_checkpoint_messages_log[key]))
            state_counts = {}
            for i in range(len(states)):
                if states[i] not in state_counts:
                    state_counts[states[i]] = 1
                else:
                    state_counts[states[i]] = state_counts[states[i]] + 1
            max_idx = np.argmax(list(state_counts.values()))
            if list(state_counts.values())[max_idx] >= self.fault_threshold:
                return True
        return False

    def accept(self, commit: minbft_manager_pb2.CommitMsg) -> None:
        """
        Accept a given commit

        :param commit: the commit to accept
        :return: None
        """
        if commit.message.operationType == OperationType.WRITE.value:
            self.state = commit.message.operationData
        key = (commit.message.clientIp, commit.message.clientPort, commit.message.clientId,
               commit.message.sequenceNumber)
        if key in self.view_change_trigger_threads:
            self.view_change_trigger_threads[key].stopped = True
            del self.view_change_trigger_threads[key]
        self.commits[key] = (commit, self.state)
        key_2 = (commit.message.clientIp, commit.message.clientPort, commit.message.clientId,
                 commit.message.sequenceNumber, commit.leaderUniqueIdentifier.uniqueIdentifier, commit.viewId)
        self.commit_log.append(key_2)
        self.reply_to_client(client_request=commit.message)

    def reply_to_client(self, client_request: minbft_manager_pb2.ServiceRequestMsg) -> None:
        """
        Utility function for replying to a service request by a client

        :param client_request: the request to reply to
        :return: None
        """
        key = (client_request.clientIp, client_request.clientPort, client_request.clientId,
               client_request.sequenceNumber)
        if key in self.commits:
            state = self.commits[key][1]
            with grpc.insecure_channel(f"{client_request.clientIp}:{client_request.clientPort}") as channel:
                stub = minbft_client_manager_pb2_grpc.MinbftClientManagerStub(channel)
                client_service_reply_msg = minbft_client_manager_pb2.ClientServiceReplyMsg(
                    nodeIp=self.ip, nodePort=self.port, nodeId=self.id,
                    sequenceNumber=client_request.sequenceNumber, state=state,
                    operationType=client_request.operationType, operationData=client_request.operationData,
                    signature=client_request.signature
                )
                stub.serviceReply(client_service_reply_msg)

    def createUI(self, request: minbft_manager_pb2.CreateUIMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.USIGCertificateDTO:
        """
        Creates a USIG certificate for a given message (see Giuliana Santos Veronese et al, 2011)

        :param request: the gRPC request
        :param context: the gRCP context
        :return: the USIG certificate
        """
        usig_certificate: minbft_manager_pb2.USIGCertificateDTO = self.local_create_UI(request_message=request)
        self.V_acc[(self.ip, self.port, self.id)] = usig_certificate.uniqueIdentifier
        return usig_certificate

    def verifyUI(self, request: minbft_manager_pb2.USIGCertificateDTO, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.UIVerificationDTO:
        """
        Validates a given a USIG certificate (see Giuliana Santos Veronese et al, 2011)

        :param request: the gRPC request
        :param context: the gRPC context
        :return: A UIVerificationDTO with the verification result
        """
        message = f"{request.message}-{self.ip}-{self.port}-{self.id}-{request.uniqueIdentifier}"
        valid = CryptoUtil.verify_signature(message=request.message, signature=request.signature,
                                            rsa_public_key=self.public_rsa_key)
        valid = valid and int(message.split("-")[-1]) == request.uniqueIdentifier
        valid_dto = minbft_manager_pb2.UIVerificationDTO(valid=valid)
        return valid_dto

    def compromise(self, request: minbft_manager_pb2.CompromiseMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.CompromisedDTO:
        """
        Updates the compromise status of the node

        :param request: the gRPC request
        :param context: the gRPC context
        :return: the updated compromised status of the node (a CompromisedDTO)
        """
        self.compromised = True
        logging.info(f"Compromised node: {self.ip}, {self.port}, {self.id}")
        compromised_dto = minbft_manager_pb2.CompromisedDTO(compromised=self.compromised)
        return compromised_dto

    def getCompromisedStatus(self, request: minbft_manager_pb2.GetCompromisedStatusMsg,
                             context: grpc.ServicerContext) -> minbft_manager_pb2.CompromisedDTO:
        """
        Gets the compromised status of the node

        :param request: the gRPC request
        :param context: the gRPC context
        :return: the compromised status of the node (a CompromisedDTO)
        """
        compromised_dto = minbft_manager_pb2.CompromisedDTO(compromised=self.compromised)
        return compromised_dto

    def crash(self, request: minbft_manager_pb2.CrashMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.CrashedDTO:
        """
        Updates the crashed status of the node

        :param request: the gRPC request
        :param context: the gRPC context
        :return: the updated crashed status of the node (a CrashedDTO)
        """
        logging.info(f"Crashed node: {self.ip}, {self.port}, {self.id}")
        self.crashed = True
        crashed_dto = minbft_manager_pb2.CrashedDTO(crashed=self.crashed)
        return crashed_dto

    def getCrashedStatus(self, request: minbft_manager_pb2.GetCrashedStatusMsg,
                         context: grpc.ServicerContext) -> minbft_manager_pb2.CrashedDTO:
        """
        Gets the crashed status of the node

        :param request: the gRPC request
        :param context: the gRPC context
        :return: the crashed status of the node (a CrashedDTO)
        """
        crashed_dto = minbft_manager_pb2.CrashedDTO(crashed=self.crashed)
        return crashed_dto

    def getClients(self, request: minbft_manager_pb2.GetClientsMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.ClientsDTO:
        """
        Gets the clients configuration

        :param request: the gRPC request
        :param context: the gRPC context
        :return: A ClientsDTO with the client ids and public keys
        """
        return minbft_manager_pb2.ClientsDTO(clientIps=self.client_ips, clientPorts=self.client_ports,
                                             publicKeys=self.clients_public_keys)

    def setClients(self, request: minbft_manager_pb2.ClientsDTO, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.ClientsDTO:
        """
        Gets the clients configuration

        :param request: the gRPC request
        :param context: the gRPC context
        :return: A ClientsDTO with the client ids and public keys
        """
        self.client_ips = list(request.clientIps)
        self.client_ports = list(request.clientPorts)
        self.client_ids = list(request.clientIds)
        self.clients_public_keys = list(request.publicKeys)
        for i in range(len(self.client_ips)):
            if (self.client_ips[i], self.client_ports[i], self.client_ids[i]) not in self.V_req:
                self.V_req[(self.client_ips[i], self.client_ports[i], self.client_ids[i])] = -1
        return minbft_manager_pb2.ClientsDTO(clientIps=self.client_ips, clientPorts=self.client_ports,
                                             publicKeys=self.clients_public_keys)

    def serviceRequest(self, request: minbft_manager_pb2.ServiceRequestMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.Ack:
        """
        Serves a service request by a client

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        if self.crashed:
            return minbft_manager_pb2.Ack()

        if len(self.commit_log) > 0 and self.commit_log[-1][4] % self.checkpoint_period == 0:
            self.initiate_checkpoint()

        if self.pending_view_change:
            return minbft_manager_pb2.Ack()

        if self.is_client_request_valid(client_reqest=request):
            prepare_sent = self.send_prepare(request=request)
            if prepare_sent and self.am_i_leader():
                key = (request.clientIp, request.clientPort, request.clientId, request.sequenceNumber, self.view_id)
                prepare_msg = self.prepare_messages_log[key]
                self.broadcast_commit(prepare_msg=prepare_msg, usig_certificate=prepare_msg.uniqueIdentifier)
            else:
                if request.sequenceNumber > self.V_req[(request.clientIp, request.clientPort, request.clientId)]:
                    key = (request.clientIp, request.clientPort, request.clientId, request.sequenceNumber)
                    if key not in self.view_change_trigger_threads:
                        view_change_trigger_thread = ViewChangeTriggerThread(
                            client_ip=request.clientIp, client_port=request.clientPort, client_id=request.clientId,
                            sequence_number=request.sequenceNumber,
                            node_ip=self.ip, node_port=self.port, leader_timeout_seconds=self.leader_timeout_seconds)
                        view_change_trigger_thread.start()
                        self.view_change_trigger_threads[key] = view_change_trigger_thread

        return minbft_manager_pb2.Ack()

    def prepare(self, request: minbft_manager_pb2.PrepareMsg, context: grpc.ServicerContext) -> minbft_manager_pb2.Ack:
        """
        Handler for the <prepare> message from the leader

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        if self.crashed:
            return minbft_manager_pb2.Ack()

        if self.am_i_leader():
            # Leader should never receive prepare
            return minbft_manager_pb2.Ack()

        key = (request.message.clientIp, request.message.clientPort,
               request.message.clientId, request.message.sequenceNumber, request.viewId)

        # Validate prepare message and client request
        if (not self.is_prepare_message_valid(prepare_msg=request) or
                not self.is_client_request_valid(client_reqest=request.message)):
            return minbft_manager_pb2.Ack()

        # Validate the UI is above low watermark
        if request.uniqueIdentifier.uniqueIdentifier < self.low_watermark:
            return minbft_manager_pb2.Ack()

        # Validate the UI is below high watermark
        if request.uniqueIdentifier.uniqueIdentifier > (self.low_watermark + self.maximum_log_size):
            return minbft_manager_pb2.Ack()

        # Validate leader USIG
        with grpc.insecure_channel(f"{request.leaderIp}:{request.leaderPort}") as channel:
            stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
            if not stub.verifyUI(request.uniqueIdentifier).valid:
                return minbft_manager_pb2.Ack()

        # If we have not yet installed the view we cannot accept the commit
        if self.pending_view_change:
            self.V_acc[(request.leaderIp, request.leaderPort, request.leaderId)] = max(
                request.uniqueIdentifier.uniqueIdentifier,
                self.V_acc[(request.leaderIp, request.leaderPort, request.leaderId)])

        if key not in self.received_prepare_messages_log:
            # If it is a new prepare, validate sequential USIG
            if not self.is_ui_sequential(unique_identifier=request.uniqueIdentifier,
                                         node_ip=request.leaderIp, node_port=request.leaderPort,
                                         node_id=request.leaderId):
                key = (request.leaderIp, request.leaderPort, request.leaderId)
                logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) invalid sequential USIG, {self.V_acc[key]}, "
                             f"{request.uniqueIdentifier.uniqueIdentifier}, {request.message.sequenceNumber}")
                return minbft_manager_pb2.Ack()

        # Prepare msg is valid, broadcast commit
        # Check if we have already seen this prepare message
        if key in self.received_prepare_messages_log:
            usig_certificate: minbft_manager_pb2.USIGCertificateDTO = (
                self.commit_messages_log[key].followerUniqueIdentifier)
        else:
            request_msg = \
                f"{request.message.clientIp}-{request.message.clientPort}-" \
                f"{request.message.sequenceNumber}-" \
                f"{request.message.operationType}-" \
                f"{request.message.operationData}"
            usig_certificate: minbft_manager_pb2.USIGCertificateDTO = self.local_create_UI(request_message=request_msg)
            self.V_acc[(self.ip, self.port, self.id)] = usig_certificate.uniqueIdentifier
        self.V_acc[(request.leaderIp, request.leaderPort, request.leaderId)] = max(
            request.uniqueIdentifier.uniqueIdentifier,
            self.V_acc[(request.leaderIp, request.leaderPort, request.leaderId)])
        self.add_received_prepare_to_message_queue(prepare=request)
        self.broadcast_commit(prepare_msg=request, usig_certificate=usig_certificate)
        return minbft_manager_pb2.Ack()

    def commit(self, request: minbft_manager_pb2.CommitMsg, context: grpc.ServicerContext) -> minbft_manager_pb2.Ack:
        """
        Handler for the <commit> message from the leader

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        if self.crashed:
            return minbft_manager_pb2.Ack()

        # Check that we have not already accepted the commit
        if len(self.commit_log) > 0 and request.leaderUniqueIdentifier.uniqueIdentifier <= self.commit_log[-1][4]:
            return minbft_manager_pb2.Ack()

        # Validate commit message
        if not self.is_commit_message_valid(commit_msg=request) or not self.is_client_request_valid(request.message):
            logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) invalid commit")
            return minbft_manager_pb2.Ack()

        # Validate the UI is above low watermark
        if request.leaderUniqueIdentifier.uniqueIdentifier < self.low_watermark:
            logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) invalid commit1")
            return minbft_manager_pb2.Ack()

        # Validate the UI is below high watermark
        if request.leaderUniqueIdentifier.uniqueIdentifier > (self.low_watermark + self.maximum_log_size):
            logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) invalid commit2")
            return minbft_manager_pb2.Ack()

        # Validate leader UI
        with grpc.insecure_channel(f"{request.leaderIp}:{request.leaderPort}") as channel:
            stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
            if not stub.verifyUI(request.leaderUniqueIdentifier).valid:
                logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) invalid commit3")
                return minbft_manager_pb2.Ack()

        # If we have not installed the view we cannot accept a commit.
        if self.pending_view_change:
            self.V_acc[(request.leaderIp, request.leaderPort, request.leaderId)] = max(
                request.leaderUniqueIdentifier.uniqueIdentifier,
                self.V_acc[(request.leaderIp, request.leaderPort, request.leaderId)])

        # Validate leader sequential USIG
        if not self.is_ui_sequential(unique_identifier=request.leaderUniqueIdentifier,
                                     node_ip=request.leaderIp, node_port=request.leaderPort, node_id=request.leaderId):
            logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) invalid commit4, leader:{self.leader_id}, "
                         f"{request.leaderUniqueIdentifier.uniqueIdentifier}, {self.V_acc}")
            return minbft_manager_pb2.Ack()

        # Validate follower UI
        with grpc.insecure_channel(f"{request.followerIp}:{request.followerPort}") as channel:
            stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
            if not stub.verifyUI(request.followerUniqueIdentifier).valid:
                logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) invalid commit5")
                return minbft_manager_pb2.Ack()

        if not self.am_i_leader():
            # If we have not seen the prepare before and we are not leader, broadcast our commit
            key = (request.message.clientIp, request.message.clientPort, request.message.clientId,
                   request.message.sequenceNumber, request.viewId)
            if key not in self.received_prepare_messages_log:
                prepare_msg = minbft_manager_pb2.PrepareMsg(
                    viewId=self.view_id,
                    leaderIp=request.leaderIp,
                    leaderPort=request.leaderPort,
                    leaderId=request.leaderId,
                    message=request.message,
                    uniqueIdentifier=request.leaderUniqueIdentifier
                )
                self.add_received_prepare_to_message_queue(prepare=prepare_msg)
                request_msg = \
                    f"{request.message.clientIp}-{request.message.clientPort}-" \
                    f"{request.message.sequenceNumber}-" \
                    f"{request.message.operationType}-" \
                    f"{request.message.operationData}"
                usig_certificate: minbft_manager_pb2.USIGCertificateDTO = self.local_create_UI(
                    request_message=request_msg)
                self.V_acc[(request.leaderIp, request.leaderPort, request.leaderId)] = max(
                    request.leaderUniqueIdentifier.uniqueIdentifier,
                    self.V_acc[(request.leaderIp, request.leaderPort, request.leaderId)])
                self.broadcast_commit(prepare_msg=prepare_msg, usig_certificate=usig_certificate)

        # Log the validated commit
        self.V_acc[(request.leaderIp, request.leaderPort, request.leaderId)] = (
            max(request.leaderUniqueIdentifier.uniqueIdentifier,
                self.V_acc[(request.leaderIp, request.leaderPort, request.leaderId)]))
        self.V_acc[(request.followerIp, request.followerPort, request.followerId)] = (
            max(request.followerUniqueIdentifier.uniqueIdentifier,
                self.V_acc[(request.followerIp, request.followerPort, request.followerId)]))
        self.add_received_commit_to_message_queue(commit=request)
        if self.has_a_quorum_been_reached(commit=request):
            self.accept(commit=request)
        return minbft_manager_pb2.Ack()

    def checkpoint(self, request: minbft_manager_pb2.CheckpointMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.Ack:
        """
        Handler for the <checkpoint> message

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        if self.crashed:
            return minbft_manager_pb2.Ack()

        self.V_acc[(request.nodeIp, request.nodePort, request.nodeId)] = (
            max(request.nodeUniqueIdentifier.uniqueIdentifier,
                self.V_acc[(request.nodeIp, request.nodePort, request.nodeId)]))

        # Verify that it is not an old checkpoint
        if request.checkpointUniqueIdentifier.uniqueIdentifier <= self.low_watermark:
            return minbft_manager_pb2.Ack()

        # Verify that the view ID matches
        if not request.viewId == self.view_id:
            logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) checkpoint invalid view")
            return minbft_manager_pb2.Ack()

        # Validate leader USIG
        with grpc.insecure_channel(f"{request.leaderIp}:{request.leaderPort}") as channel:
            stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
            if not stub.verifyUI(request.checkpointUniqueIdentifier).valid:
                logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) checkpoint invalid leader usig")
                return minbft_manager_pb2.Ack()

        # Validate node USIG
        with grpc.insecure_channel(f"{request.nodeIp}:{request.nodePort}") as channel:
            stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
            if not stub.verifyUI(request.nodeUniqueIdentifier).valid:
                logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) checkpoint invalid usig")
                return minbft_manager_pb2.Ack()

        # Validate node sequential USIG
        if not self.is_ui_sequential(unique_identifier=request.nodeUniqueIdentifier,
                                     node_ip=request.nodeIp, node_port=request.nodePort,
                                     node_id=request.nodeId):
            logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) checkpoint invalid seq")
            return minbft_manager_pb2.Ack()

        self.add_received_checkpoint_to_message_queue(checkpoint=request)
        if self.has_a_checkpoint_quorum_been_reached(checkpoint=request):
            self.accept_checkpoint(checkpoint_msg=request)
        return minbft_manager_pb2.Ack()

    def accept_checkpoint(self, checkpoint_msg: minbft_manager_pb2.CheckpointMsg):
        """
        Accepts a given checkpoint with a certificate

        :param checkpoint_msg: the checkpoint to accept
        :return: None
        """
        logging.info(f"Node: ({self.ip}, {self.port}, {self.id}) reached checkpoint certificate "
                     f"with UI: {checkpoint_msg.checkpointUniqueIdentifier.uniqueIdentifier}")
        self.low_watermark = checkpoint_msg.checkpointUniqueIdentifier.uniqueIdentifier
        key = (checkpoint_msg.checkpointUniqueIdentifier.uniqueIdentifier, checkpoint_msg.viewId)
        self.checkpoint_certificate = self.received_checkpoint_messages_log[key]
        self.checkpoint_state = checkpoint_msg.state
        self.cleanup_logs(checkpoint_unique_identifier=checkpoint_msg.checkpointUniqueIdentifier.uniqueIdentifier)

    def triggerViewChange(self, request: minbft_manager_pb2.TriggerViewChangeMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.Ack:
        """
        Handler for the triggerViewChange method

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        for _, thread in self.view_change_trigger_threads.items():
            thread.stopped = True
        if self.crashed:
            return minbft_manager_pb2.Ack()
        key = (request.clientIp, request.clientPort, request.clientId, request.sequenceNumber)
        if key not in self.view_change_trigger_threads:
            return minbft_manager_pb2.Ack()
        request_view_change_msg = minbft_manager_pb2.RequestViewChangeMsg(
            viewId=self.view_id, newViewId=self.view_id + 1, nodeIp=self.ip, nodePort=self.port,
            nodeId=self.id
        )
        self.broadcast_request_view_change(request_view_change_msg=request_view_change_msg)
        return minbft_manager_pb2.Ack()

    def requestViewChange(self, request: minbft_manager_pb2.RequestViewChangeMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.Ack:
        """
        Handler for the requestViewChange method

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        if self.crashed:
            return minbft_manager_pb2.Ack()
        if request.newViewId <= self.view_id:
            return minbft_manager_pb2.Ack()
        if request.newViewId in self.received_request_view_change_messages:
            duplicate = False
            for view_change_msg in self.received_request_view_change_messages[request.newViewId]:
                if view_change_msg.nodeId == request.nodeId:
                    duplicate = True
            if not duplicate:
                self.received_request_view_change_messages[request.newViewId].append(request)
        else:
            self.received_request_view_change_messages[request.newViewId] = [request]
        if self.has_a_request_view_change_quorum_been_reached(request_view_change_msg=request):
            self.view_id = request.newViewId
            self.pending_view_change = True
            leader_idx = self.view_id % len(self.node_ips)
            self.leader_id = self.node_ids[leader_idx]
            self.leader_ip = self.node_ips[leader_idx]
            self.leader_port = self.node_ports[leader_idx]
            prepare_messages = []
            for k, v in self.prepare_messages_log.items():
                prepare_messages.append(v)
            commit_messages = []
            for k, v in self.commit_messages_log.items():
                commit_messages.append(v)
            view_change_messages = []
            for k, view_change_msg in self.view_change_message_log.items():
                view_change_messages.append(view_change_msg)
            new_view_messages = []
            for k, new_view_msg in self.new_view_message_log.items():
                new_view_messages.append(new_view_msg)
            view_change_id = f"{self.ip}-{self.port}-{self.id}-{self.view_id}-viewchange"
            usig_certificate: minbft_manager_pb2.USIGCertificateDTO = self.local_create_UI(
                request_message=view_change_id)
            self.V_acc[(self.ip, self.port, self.id)] = usig_certificate.uniqueIdentifier
            view_change_msg = minbft_manager_pb2.ViewChangeMsg(
                viewId=self.view_id, nodeIp=self.ip, nodePort=self.port, nodeId=self.id,
                checkpointState=self.checkpoint_state, checkpointWatermark=self.low_watermark,
                checkpointCertificate=self.checkpoint_certificate, prepareMessages=prepare_messages,
                commitMessages=commit_messages, viewChangeMessages=view_change_messages,
                newViewMessages=new_view_messages, nodeUniqueIdentifier=usig_certificate
            )
            self.broadcast_view_change(view_change_msg=view_change_msg)
        return minbft_manager_pb2.Ack()

    def validate_view_change_msg(self, view_change_msg: minbft_manager_pb2.ViewChangeMsg) -> bool:
        """
        Validates a given view_change_msg

        :param view_change_msg: the message to validate
        :return: True if valid else False
        """
        ui_numbers = set()
        max_cv_in_messages = -1

        # Validate signatures of prepare messages
        for i in range(len(view_change_msg.prepareMessages)):
            prepare_msg = view_change_msg.prepareMessages[i]
            with grpc.insecure_channel(f"{prepare_msg.leaderIp}:{prepare_msg.leaderPort}") as channel:
                stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                if not stub.verifyUI(prepare_msg.uniqueIdentifier).valid:
                    if view_change_msg.viewId == 2:
                        logging.info(f"Node: {view_change_msg.nodeId} invalid prepare")
                    return False
                else:
                    max_cv_in_messages = max([max_cv_in_messages, prepare_msg.uniqueIdentifier.uniqueIdentifier])
                    ui_numbers.add(prepare_msg.uniqueIdentifier.uniqueIdentifier)

        # Validate signatures of commit messages
        for i in range(len(view_change_msg.commitMessages)):
            commit_msg = view_change_msg.commitMessages[i]
            with grpc.insecure_channel(f"{commit_msg.leaderIp}:{commit_msg.leaderPort}") as channel:
                stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                if not stub.verifyUI(commit_msg.leaderUniqueIdentifier).valid:
                    logging.info(f"Node: {view_change_msg.nodeId} invalid commit1")
                    return False
            with grpc.insecure_channel(f"{commit_msg.followerIp}:{commit_msg.followerPort}") as channel:
                stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                if not stub.verifyUI(commit_msg.followerUniqueIdentifier).valid:
                    logging.info(f"Node: {view_change_msg.nodeId} invalid commit2")
                    return False
                max_cv_in_messages = max([max_cv_in_messages, commit_msg.followerUniqueIdentifier.uniqueIdentifier])
                ui_numbers.add(commit_msg.followerUniqueIdentifier.uniqueIdentifier)

        # Validate signatures of view change messages
        for i in range(len(view_change_msg.viewChangeMessages)):
            prev_view_change_msg = view_change_msg.viewChangeMessages[i]
            with grpc.insecure_channel(f"{prev_view_change_msg.nodeIp}:{prev_view_change_msg.nodePort}") as channel:
                stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                if not stub.verifyUI(prev_view_change_msg.nodeUniqueIdentifier).valid:
                    logging.info(f"Node: {view_change_msg.nodeId} invalid view change sign")
                    return False
                max_cv_in_messages = max(
                    [max_cv_in_messages, prev_view_change_msg.nodeUniqueIdentifier.uniqueIdentifier])
                ui_numbers.add(prev_view_change_msg.nodeUniqueIdentifier.uniqueIdentifier)

        # Validate signatures of new-view messages
        for i in range(len(view_change_msg.newViewMessages)):
            new_view_msg = view_change_msg.newViewMessages[i]
            with grpc.insecure_channel(f"{new_view_msg.nodeIp}:{new_view_msg.nodePort}") as channel:
                stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                if not stub.verifyUI(new_view_msg.nodeUniqueIdentifier).valid:
                    logging.info(f"Node: {view_change_msg.nodeId} invalid new view sign")
                    return False
                max_cv_in_messages = max([max_cv_in_messages, new_view_msg.nodeUniqueIdentifier.uniqueIdentifier])
                ui_numbers.add(new_view_msg.nodeUniqueIdentifier.uniqueIdentifier)

        # Validate signature
        with grpc.insecure_channel(f"{view_change_msg.nodeIp}:{view_change_msg.nodePort}") as channel:
            stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
            if not stub.verifyUI(view_change_msg.nodeUniqueIdentifier).valid:
                logging.info(f"Node: {view_change_msg.nodeId} invalid view change sign")
                return False
        O_empty = False
        if max_cv_in_messages == -1:
            O_empty = True

        checkpoint_node_start = 0
        # Validate checkpoint certificate
        for i in range(len(view_change_msg.checkpointCertificate)):
            checkpoint_msg = view_change_msg.checkpointCertificate[i]
            # Validate node signature of checkpoint msg
            with grpc.insecure_channel(f"{checkpoint_msg.nodeIp}:{checkpoint_msg.nodePort}") as channel:
                stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                if not stub.verifyUI(checkpoint_msg.nodeUniqueIdentifier).valid:
                    logging.info(f"Node: {view_change_msg.nodeId} invalid checkpoint cert")
                    return False
                if checkpoint_msg.nodeId == view_change_msg.nodeId:
                    ui_numbers.add(checkpoint_msg.nodeUniqueIdentifier.uniqueIdentifier)
                    checkpoint_node_start = checkpoint_msg.nodeUniqueIdentifier.uniqueIdentifier
                if O_empty:
                    max_cv_in_messages = max([max_cv_in_messages, checkpoint_msg.nodeUniqueIdentifier.uniqueIdentifier])

            # Validate leader signature of checkpoint msg
            with grpc.insecure_channel(f"{checkpoint_msg.leaderIp}:{checkpoint_msg.leaderPort}") as channel:
                stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                if not stub.verifyUI(checkpoint_msg.checkpointUniqueIdentifier).valid:
                    logging.info(f"Node: {view_change_msg.nodeId} invalid checkpoint cert2")
                    return False

        # Validate UI sequential consistency
        ui_numbers_list = list(ui_numbers)
        start_point = max(checkpoint_node_start, view_change_msg.checkpointWatermark)
        ui_numbers_list = list(filter(lambda x: x > start_point, ui_numbers_list))
        # if len(ui_numbers_list) > 10:
        ui_numbers_list.sort()
        for i in range(1, len(ui_numbers_list)):
            if not ui_numbers_list[i] == (ui_numbers_list[i - 1] + 1):
                logging.info(f"Node: {view_change_msg.nodeId} "
                             f"invalid sequential from: {view_change_msg.nodeIp}, {ui_numbers_list[i]}, "
                             f"{ui_numbers_list}, {ui_numbers}")
                return False

        # Validate UI value
        if not view_change_msg.nodeUniqueIdentifier.uniqueIdentifier == (max_cv_in_messages + 1):
            logging.info(f"Node: {view_change_msg.nodeId} invalid UI value, "
                         f"{view_change_msg.nodeUniqueIdentifier.uniqueIdentifier}, {(max_cv_in_messages + 1)}")
            return False

        return True

    def create_S(self, view_change_certificate: List[minbft_manager_pb2.ViewChangeMsg]) \
            -> Tuple[List[minbft_manager_pb2.PrepareMsg], List[minbft_manager_pb2.CommitMsg],
            List[minbft_manager_pb2.ViewChangeMsg], List[minbft_manager_pb2.NewViewMsg],
            List[minbft_manager_pb2.CheckpointMsg], int, int]:
        """
        Creates the state after a view change

        :param view_change_certificate: the view change certificate
        :return: prepareMessages, commitMessages, viewChangeMessages, newViewMessages,
                 most_recent_checkpoint_certificate, most_recent_checkpoint_certificate_watermark,
                 most_recent_checkpoint_state
        """
        most_recent_checkpoint_certificate_watermark = view_change_certificate[0].checkpointWatermark
        most_recent_checkpoint_certificate = view_change_certificate[0].checkpointCertificate
        most_recent_checkpoint_state = view_change_certificate[0].checkpointState
        for i in range(1, len(view_change_certificate)):
            if view_change_certificate[i].checkpointWatermark > most_recent_checkpoint_certificate_watermark:
                most_recent_checkpoint_certificate_watermark = view_change_certificate[i].checkpointWatermark
                most_recent_checkpoint_certificate = view_change_certificate[i].checkpointCertificate
                most_recent_checkpoint_state = view_change_certificate[i].checkpointState
        prepare_messages = []
        commit_messages = []
        view_change_messages = []
        new_view_messages = []
        for i in range(len(view_change_certificate)):
            for prepare_msg in view_change_certificate[i].prepareMessages:
                if prepare_msg.uniqueIdentifier.uniqueIdentifier > most_recent_checkpoint_certificate_watermark:
                    prepare_messages.append(prepare_msg)
            for commit_msg in view_change_certificate[i].commitMessages:
                if (commit_msg.leaderUniqueIdentifier.uniqueIdentifier >
                        most_recent_checkpoint_certificate_watermark):
                    commit_messages.append(commit_msg)
            for view_change_msg in view_change_certificate[i].viewChangeMessages:
                if (view_change_msg.nodeUniqueIdentifier.uniqueIdentifier >
                        most_recent_checkpoint_certificate_watermark):
                    view_change_messages.append(view_change_msg)
            for new_view_msg in view_change_certificate[i].newViewMessages:
                if (new_view_msg.nodeUniqueIdentifier.uniqueIdentifier >
                        most_recent_checkpoint_certificate_watermark):
                    new_view_messages.append(new_view_msg)
        prepare_messages.sort(key=lambda x: x.uniqueIdentifier.uniqueIdentifier)
        commit_messages.sort(key=lambda x: x.leaderUniqueIdentifier.uniqueIdentifier)
        return (prepare_messages, commit_messages, view_change_messages, new_view_messages,
                most_recent_checkpoint_certificate, most_recent_checkpoint_certificate_watermark,
                most_recent_checkpoint_state)

    def viewChange(self, request: minbft_manager_pb2.ViewChangeMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.Ack:
        """
        Handler for the viewChange method

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        if self.crashed:
            return minbft_manager_pb2.Ack()

        # Check if its is an old view change
        if not self.pending_view_change:
            return minbft_manager_pb2.Ack()
        if request.viewId < self.view_id:
            return minbft_manager_pb2.Ack()

        valid = self.validate_view_change_msg(view_change_msg=request)
        if not valid:
            return minbft_manager_pb2.Ack()

        key = (request.nodeIp, request.nodePort, request.nodeId)
        self.V_acc[key] = max(self.V_acc[key], request.nodeUniqueIdentifier.uniqueIdentifier)

        # Store the validated view change msg
        if request.viewId not in self.received_view_change_message_log:
            self.received_view_change_message_log[request.viewId] = [request]
        else:
            self.received_view_change_message_log[request.viewId].append(request)

        if self.am_i_leader() and self.has_a_view_change_quorum_been_reached(view_change_msg=request):
            self.new_view_certificate = self.received_view_change_message_log[request.viewId]
            (prepare_messages, commit_messages, view_change_messages, new_view_messages,
             most_recent_checkpoint_certificate,
             most_recent_checkpoint_certificate_watermark, most_recent_checkpoint_state) = (
                self.create_S(view_change_certificate=self.new_view_certificate))

            # Update state
            self.checkpoint_certificate = most_recent_checkpoint_certificate
            self.low_watermark = most_recent_checkpoint_certificate_watermark
            self.checkpoint_state = most_recent_checkpoint_state

            for view_change_msg in self.new_view_certificate:
                key = (view_change_msg.nodeIp, view_change_msg.nodePort, view_change_msg.nodeId)
                self.V_acc[key] = max(view_change_msg.nodeUniqueIdentifier.uniqueIdentifier, self.V_acc[key])

            # Apply pending operations
            self.apply_pending_operations(commit_messages=commit_messages, prepare_messages=prepare_messages)

            # New view message
            view_change_id = f"{self.ip}-{self.port}-{self.id}-{self.view_id}-newview"
            usig_certificate: minbft_manager_pb2.USIGCertificateDTO = self.local_create_UI(
                request_message=view_change_id)
            self.V_acc[(self.ip, self.port, self.id)] = usig_certificate.uniqueIdentifier
            new_view_msg = minbft_manager_pb2.NewViewMsg(
                viewId=self.view_id, nodeIp=self.ip, nodePort=self.port, nodeId=self.id,
                newViewCertificate=self.new_view_certificate, prepareMessages=prepare_messages,
                commitMessages=commit_messages, viewChangeMessages=view_change_messages, newViewMessages=new_view_messages,
                nodeUniqueIdentifier=usig_certificate
            )
            self.broadcast_new_view(new_view_msg=new_view_msg)

        return minbft_manager_pb2.Ack()

    def newView(self, request: minbft_manager_pb2.NewViewMsg, context: grpc.ServicerContext) \
            -> minbft_manager_pb2.Ack:
        """
        Handler for the <NewView> message

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        if self.crashed:
            return minbft_manager_pb2.Ack()

        # Validate view
        if not self.view_id == request.viewId:
            return minbft_manager_pb2.Ack()

        # Validate certificate
        for view_change_msg in request.newViewCertificate:
            if not self.validate_view_change_msg(view_change_msg=view_change_msg):
                return minbft_manager_pb2.Ack()

        # Reconstruct state
        (prepareMessages, commitMessages, viewChangeMessages, newViewMessages, most_recent_checkpoint_certificate,
         most_recent_checkpoint_certificate_watermark, most_recent_checkpoint_state) = self.create_S(
            view_change_certificate=request.newViewCertificate)

        # Validate state
        if not len(prepareMessages) == len(request.prepareMessages):
            return minbft_manager_pb2.Ack()
        if not len(commitMessages) == len(request.commitMessages):
            return minbft_manager_pb2.Ack()
        if not len(viewChangeMessages) == len(request.viewChangeMessages):
            return minbft_manager_pb2.Ack()
        if not len(newViewMessages) == len(request.newViewMessages):
            return minbft_manager_pb2.Ack()
        for i in range(len(prepareMessages)):
            if not self.prepare_msg_equal(msg_1=prepareMessages[i], msg_2=request.prepareMessages[i]):
                return minbft_manager_pb2.Ack()
        for i in range(len(commitMessages)):
            if not self.commit_msg_equal(msg_1=commitMessages[i], msg_2=request.commitMessages[i]):
                return minbft_manager_pb2.Ack()
        for i in range(len(viewChangeMessages)):
            if not self.view_change_msg_equal(msg_1=viewChangeMessages[i], msg_2=request.viewChangeMessages[i]):
                return minbft_manager_pb2.Ack()
        for i in range(len(newViewMessages)):
            if not self.new_view_msg_equal(msg_1=newViewMessages[i], msg_2=request.newViewMessages[i]):
                return minbft_manager_pb2.Ack()

        # Update view certificate
        self.new_view_certificate = request.newViewCertificate

        # Apply pending operations
        self.apply_pending_operations(commit_messages=commitMessages, prepare_messages=prepareMessages)

        # Update V_acc
        for view_change_msg in request.newViewCertificate:
            key = (view_change_msg.nodeIp, view_change_msg.nodePort, view_change_msg.nodeId)
            self.V_acc[key] = max(view_change_msg.nodeUniqueIdentifier.uniqueIdentifier, self.V_acc[key])
        key = (request.nodeIp, request.nodePort, request.nodeId)
        self.V_acc[key] = max(request.nodeUniqueIdentifier.uniqueIdentifier, self.V_acc[key])
        logging.info(f"({self.ip}, {self.port}, {self.id}) accepted new view: {request.viewId}")
        self.pending_view_change = False
        if request.viewId in self.received_request_view_change_messages:
            del self.received_request_view_change_messages[request.viewId]
        return minbft_manager_pb2.Ack()

    def apply_pending_operations(self, commit_messages: List[minbft_manager_pb2.CommitMsg],
                                 prepare_messages:[minbft_manager_pb2.PrepareMsg]) -> None:
        """
        Applies a list of pending commit and prepare operations

        :param commit_messages: the list of pending commit operations
        :param prepare_messages: the list of pending prepare operations
        :return: None
        """
        for commit in commit_messages:
            key = (commit.message.clientIp, commit.message.clientPort, commit.message.clientId,
                   commit.message.sequenceNumber, commit.leaderUniqueIdentifier.uniqueIdentifier, commit.viewId)
            if key not in self.commit_log:
                self.state = commit.message.operationData
        for prepare_msg in prepare_messages:
            key = (prepare_msg.message.clientIp, prepare_msg.message.clientPort, prepare_msg.message.clientId,
                   prepare_msg.message.sequenceNumber, prepare_msg.viewId)
            if key not in self.received_prepare_messages_log:
                key_2 = (prepare_msg.message.clientIp, prepare_msg.message.clientPort, prepare_msg.message.clientId,
                         prepare_msg.message.sequenceNumber, prepare_msg.leaderUniqueIdentifier.uniqueIdentifier,
                         prepare_msg.viewId)
                if key_2 not in self.commit_log:
                    self.state = prepare_msg.message.operationData

    def view_change_msg_equal(self, msg_1: minbft_manager_pb2.ViewChangeMsg,
                              msg_2: minbft_manager_pb2.ViewChangeMsg) -> bool:
        """
        Utility function for checking if two view change messages are equal

        :param msg_1: first msg to compare
        :param msg_2: second msg to compare
        :return: True if equal otherwise False
        """
        equal = True
        equal = equal and msg_1.viewId == msg_2.viewId
        equal = equal and msg_1.nodeIp == msg_2.nodeIp
        equal = equal and msg_1.nodePort == msg_2.nodePort
        equal = equal and msg_1.nodeId == msg_2.nodeId
        equal = equal and msg_1.checkpointState == msg_2.checkpointState
        equal = equal and msg_1.checkpointWatermark == msg_2.checkpointWatermark
        equal = equal and len(msg_1.prepareMessages) == len(msg_2.prepareMessages)
        for i in range(len(msg_1.prepareMessages)):
            equal = equal and self.prepare_msg_equal(msg_1=msg_1.prepareMessages[i], msg_2=msg_2.prepareMessages[i])
        equal = equal and len(msg_1.commitMessages) == len(msg_2.commitMessages)
        for i in range(len(msg_1.commitMessages)):
            equal = equal and self.commit_msg_equal(msg_1=msg_1.commitMessages[i], msg_2=msg_2.commitMessages[i])
        equal = equal and len(msg_1.checkpointCertificate) == len(msg_2.checkpointCertificate)
        for i in range(len(msg_1.checkpointCertificate)):
            equal = equal and self.checkpoint_msg_equal(
                msg_1=msg_1.checkpointCertificate[i], msg_2=msg_2.checkpointCertificate[i])
        equal = equal and len(msg_1.viewChangeMessages) == len(msg_2.viewChangeMessages)
        for i in range(len(msg_1.viewChangeMessages)):
            equal = equal and self.view_change_msg_equal(
                msg_1=msg_1.viewChangeMessages[i], msg_2=msg_2.viewChangeMessages[i])
        equal = equal and len(msg_1.newViewMessages) == len(msg_2.newViewMessages)
        for i in range(len(msg_1.newViewMessages)):
            equal = equal and self.new_view_msg_equal(
                msg_1=msg_1.newViewMessages[i], msg_2=msg_2.newViewMessages[i])
        equal = equal and self.usig_certificate_equal(cert_1=msg_1.nodeUniqueIdentifier,
                                                      cert_2=msg_2.nodeUniqueIdentifier)
        return equal

    def new_view_msg_equal(self, msg_1: minbft_manager_pb2.NewViewMsg, msg_2: minbft_manager_pb2.NewViewMsg) -> bool:
        """
        Utility function for checking if two new view messages are equal

        :param msg_1: first msg to compare
        :param msg_2: second msg to compare
        :return: True if equal otherwise False
        """
        equal = True
        equal = equal and msg_1.viewId == msg_2.viewId
        equal = equal and msg_1.nodeIp == msg_2.nodeIp
        equal = equal and msg_1.nodePort == msg_2.nodePort
        equal = equal and msg_1.nodeId == msg_2.nodeId
        equal = equal and len(msg_1.viewChangeMessages) == len(msg_2.viewChangeMessages)
        for i in range(len(msg_1.viewChangeMessages)):
            equal = equal and self.view_change_msg_equal(msg_1=msg_1.viewChangeMessages[i],
                                                         msg_2=msg_2.viewChangeMessages[i])
        equal = equal and len(msg_1.newViewMessages) == len(msg_2.newViewMessages)
        for i in range(len(msg_1.newViewMessages)):
            equal = equal and self.new_view_msg_equal(msg_1=msg_1.newViewMessages[i],
                                                      msg_2=msg_2.newViewMessages[i])
        equal = equal and len(msg_1.prepareMessages) == len(msg_2.prepareMessages)
        for i in range(len(msg_1.prepareMessages)):
            equal = equal and self.prepare_msg_equal(msg_1=msg_1.prepareMessages[i], msg_2=msg_2.prepareMessages[i])
        equal = equal and len(msg_1.commitMessages) == len(msg_2.commitMessages)
        for i in range(len(msg_1.commitMessages)):
            equal = equal and self.commit_msg_equal(msg_1=msg_1.commitMessages[i], msg_2=msg_2.commitMessages[i])
        equal = equal and self.usig_certificate_equal(cert_1=msg_1.nodeUniqueIdentifier,
                                                      cert_2=msg_2.nodeUniqueIdentifier)
        return equal

    def checkpoint_msg_equal(self, msg_1: minbft_manager_pb2.CheckpointMsg,
                             msg_2: minbft_manager_pb2.CheckpointMsg) -> bool:
        """
        Utility function for checking if two checkpoint messages are equal

        :param msg_1: first msg to compare
        :param msg_2: second msg to compare
        :return: True if equal otherwise False
        """
        equal = True
        equal = equal and msg_1.viewId == msg_2.viewId
        equal = equal and msg_1.nodeIp == msg_2.nodeIp
        equal = equal and msg_1.nodePort == msg_2.nodePort
        equal = equal and msg_1.nodeId == msg_2.nodeId
        equal = equal and msg_1.leaderIp == msg_2.leaderIp
        equal = equal and msg_1.leaderPort == msg_2.leaderPort
        equal = equal and msg_1.leaderId == msg_2.leaderId
        equal = equal and msg_1.state == msg_2.state
        equal = equal and self.service_request_equal(msg_1=msg_1.message, msg_2=msg_2.message)
        equal = equal and self.usig_certificate_equal(cert_1=msg_1.checkpointUniqueIdentifier,
                                                      cert_2=msg_2.checkpointUniqueIdentifier)
        equal = equal and self.usig_certificate_equal(cert_1=msg_1.nodeUniqueIdentifier,
                                                      cert_2=msg_2.nodeUniqueIdentifier)
        return equal

    def commit_msg_equal(self, msg_1: minbft_manager_pb2.CommitMsg, msg_2: minbft_manager_pb2.CommitMsg) -> bool:
        """
        Utility function for checking if two commit messages are equal

        :param msg_1: first msg to compare
        :param msg_2: second msg to compare
        :return: True if equal otherwise False
        """
        equal = True
        equal = equal and msg_1.viewId == msg_2.viewId
        equal = equal and msg_1.leaderIp == msg_2.leaderIp
        equal = equal and msg_1.leaderPort == msg_2.leaderPort
        equal = equal and msg_1.leaderId == msg_2.leaderId
        equal = equal and msg_1.followerIp == msg_2.followerIp
        equal = equal and msg_1.followerPort == msg_2.followerPort
        equal = equal and msg_1.followerId == msg_2.followerId
        equal = equal and self.service_request_equal(msg_1=msg_1.message, msg_2=msg_2.message)
        equal = equal and self.usig_certificate_equal(cert_1=msg_1.leaderUniqueIdentifier,
                                                      cert_2=msg_2.leaderUniqueIdentifier)
        equal = equal and self.usig_certificate_equal(cert_1=msg_1.followerUniqueIdentifier,
                                                      cert_2=msg_2.followerUniqueIdentifier)
        return equal

    def prepare_msg_equal(self, msg_1: minbft_manager_pb2.PrepareMsg, msg_2: minbft_manager_pb2.PrepareMsg) -> bool:
        """
        Utility function for checking if two prepare request messages are equal

        :param msg_1: first msg to compare
        :param msg_2: second msg to compare
        :return: True if equal otherwise False
        """
        equal = True
        equal = equal and msg_1.viewId == msg_2.viewId
        equal = equal and msg_1.leaderIp == msg_2.leaderIp
        equal = equal and msg_1.leaderPort == msg_2.leaderPort
        equal = equal and msg_1.leaderId == msg_2.leaderId
        equal = equal and self.service_request_equal(msg_1=msg_1.message, msg_2=msg_2.message)
        equal = equal and self.usig_certificate_equal(cert_1=msg_1.uniqueIdentifier, cert_2=msg_2.uniqueIdentifier)
        return equal

    def service_request_equal(self, msg_1: minbft_manager_pb2.ServiceRequestMsg,
                              msg_2: minbft_manager_pb2.ServiceRequestMsg) -> bool:
        """
        Utility function for checking if two service request messages are equal

        :param msg_1: first msg to compare
        :param msg_2: second msg to compare
        :return: True if equal otherwise False
        """
        equal = True
        equal = equal and msg_1.sequenceNumber == msg_2.sequenceNumber
        equal = equal and msg_1.operationType == msg_2.operationType
        equal = equal and msg_1.operationData == msg_2.operationData
        equal = equal and msg_1.signature == msg_2.signature
        equal = equal and msg_1.clientId == msg_2.clientId
        equal = equal and msg_1.clientIp == msg_2.clientIp
        equal = equal and msg_1.clientPort == msg_2.clientPort
        return equal

    def usig_certificate_equal(self, cert_1: minbft_manager_pb2.USIGCertificateDTO,
                               cert_2: minbft_manager_pb2.USIGCertificateDTO) -> bool:
        """
        Utility function for checking if two USIG certificates are equal

        :param cert_1: first msg to compare
        :param cert_2: second msg to compare
        :return: True if equal otherwise False
        """
        equal = True
        equal = equal and cert_1.uniqueIdentifier == cert_2.uniqueIdentifier
        equal = equal and cert_1.signature == cert_2.signature
        equal = equal and cert_1.message == cert_2.message
        equal = equal and cert_1.nodeIp == cert_2.nodeIp
        equal = equal and cert_1.nodePort == cert_2.nodePort
        equal = equal and cert_1.nodeId == cert_2.nodeId
        return equal


def serve(port: int = 50044, log_dir: str = "/", max_workers: int = 10,
          log_file_name: str = "minbft_manager.log") -> None:
    """
    Starts the gRPC server for managing clients

    :param port: the port that the server will listen to
    :param log_dir: the directory to write the log file
    :param log_file_name: the file name of the log
    :param max_workers: the maximum number of GRPC workers
    :return: None
    """
    constants.LOG_FILES.MINBFT_MANAGER_LOG_DIR = log_dir
    constants.LOG_FILES.MINBFT_MANAGER_LOG_FILE = log_file_name
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    minbft_manager_pb2_grpc.add_MinbftManagerServicer_to_server(MinbftManagerServicer(port=port), server)
    server.add_insecure_port(f'[::]:{port}')
    server.start()
    logging.info(f"MinBFT node started, listening on port: {port}")
    return server


# Program entrypoint
if __name__ == '__main__':
    ports = [8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009]
    servers = list(map(lambda x: serve(port=x, log_dir="./"), ports))
    for server in servers:
        server.wait_for_termination()
