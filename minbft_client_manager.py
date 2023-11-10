from typing import List, Dict
import numpy as np
import grpc
import logging
import socket
import netifaces
import random
from concurrent import futures
import minbft_manager_pb2
import minbft_manager_pb2_grpc
import minbft_client_manager_pb2
import minbft_client_manager_pb2_grpc
from Crypto.PublicKey.RSA import RsaKey
from crypto_util import CryptoUtil
import csle_collector.constants.constants as constants
from resend_request_thread import ResendRequestThread


class MinbftClientManagerServicer(minbft_client_manager_pb2_grpc.MinbftClientManagerServicer):
    """
    gRPC node that runs the MinBFT consensus protocol
    """

    def __init__(self, port: int) -> None:
        """
        Initializes the server

        :param port: the port that the server listens to
        """
        logging.basicConfig(filename=f"{constants.LOG_FILES.MINBFT_CLIENT_MANAGER_LOG_DIR}"
                                     f"{constants.LOG_FILES.MINBFT_CLIENT_MANAGER_LOG_FILE}", level=logging.INFO)
        self.port: int = port
        self.hostname: str = socket.gethostname()
        self.ip: str = ""
        try:
            self.ip = netifaces.ifaddresses(constants.INTERFACES.ETH0)[netifaces.AF_INET][0][constants.INTERFACES.ADDR]
        except Exception:
            self.ip = socket.gethostbyname(self.hostname)
        logging.info(f"Setting up the Minbft client manager, hostname: {self.hostname} ip: {self.ip}")
        private_rsa_key, public_rsa_key = CryptoUtil.generate_rsa_keys(key_len=1024)
        self.private_rsa_key: RsaKey = private_rsa_key
        self.public_rsa_key: RsaKey = public_rsa_key
        self.node_ips: List[str] = []
        self.node_ports: List[int] = []
        self.node_ids: List[int] = []
        self.node_public_keys: List[bytes] = []
        self.id: int = -1
        self.sequence_number: int = 0
        self.fault_threshold: int = 1
        self.resend_timeout_seconds: int = 30
        self.replies: Dict[int, List[minbft_client_manager_pb2.ClientServiceReplyMsg]] = {}
        self.commit_log: List[minbft_client_manager_pb2.ClientServiceReplyMsg] = []
        self.committed_sequence_numbers: List[int] = []
        self.pending_request_threads: Dict[int, ResendRequestThread] = {}

    def send_service_request(self, operation_data: int, operation_type: int) -> None:
        """
        Sends a service request to  the cluster

        :param operation_data: the data of the request operation
        :param operation_type: the type of the request operation
        :return: None
        """
        message = (f"{self.ip}-{self.port}-{self.id}-{self.sequence_number}-{operation_type}-"
                   f"{operation_data}")
        signature = CryptoUtil.sign_message_rsa(rsa_private_key=self.private_rsa_key, message=message)
        service_request_msg = minbft_manager_pb2.ServiceRequestMsg(
            clientIp=self.ip, clientPort=self.port, sequenceNumber=self.sequence_number,
            operationType=operation_type, operationData=operation_data, signature=signature)
        logging.info(f"Client: {self.ip}, port: {self.port}, id: {self.id}, sending service request, "
                     f"sequence number: {self.sequence_number}")
        self.replies[self.sequence_number] = []
        resend_thread = ResendRequestThread(node_ports=self.node_ports, node_ips=self.node_ips,
                                            service_request_msg=service_request_msg,
                                            timeout_seconds=self.resend_timeout_seconds)
        resend_thread.start()
        self.pending_request_threads[self.sequence_number] = resend_thread
        self.sequence_number += 1

    def has_a_quorum_been_reached(self, sequence_number: int) -> bool:
        """
        Checks if a quorum of replies have been obtained for a request with a given sequence number

        :param sequence_number: the sequence number
        :return: True if a quorum has beeen reached, False otherwise
        """
        if len(self.replies[sequence_number]) > self.fault_threshold + 1:
            state_responses = list(map(lambda x: x.state, self.replies[sequence_number]))
            state_counts = {}
            for i in range(len(state_responses)):
                if state_responses[i] not in state_counts:
                    state_counts[state_responses[i]] = 1
                else:
                    state_counts[state_responses[i]] = state_counts[state_responses[i]] + 1
            max_idx = np.argmax(list(state_counts.values()))
            if list(state_counts.values())[max_idx] >= self.fault_threshold + 1:
                return True
        return False

    def accept(self, reply: minbft_client_manager_pb2.ClientServiceReplyMsg) -> False:
        """
        Accepts a given reply from the replicated service

        :param reply: the reply to accept
        :return: None
        """
        self.commit_log.append(reply)
        self.committed_sequence_numbers.append(reply.sequenceNumber)
        self.pending_request_threads[reply.sequenceNumber].stopped = True
        del self.pending_request_threads[reply.sequenceNumber]

    def send_request(self, service_request_msg: minbft_manager_pb2.ServiceRequestMsg) -> None:
        """
        Sends a request to all nodes of the system

        :param service_request_msg: the request to resend
        :return: None
        """
        for i in range(len(self.node_ips)):
            try:
                with grpc.insecure_channel(f"{self.node_ips[i]}:{self.node_ports[i]}") as channel:
                    stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                    stub.serviceRequest(service_request_msg)
            except:
                pass

    def getNodes(self, request: minbft_client_manager_pb2.GetClientNodesMsg, context: grpc.ServicerContext) \
            -> minbft_client_manager_pb2.ClientNodesDTO:
        """
        Gets the nodes configuration

        :param request: the gRPC request
        :param context: the gRPC context
        :return: A nodesDTO with the node IPs, ports, and public keys
        """
        nodes_dto = minbft_client_manager_pb2.ClientNodesDTO(nodeIps=self.node_ips, nodePorts=self.node_ports,
                                                             publicKeys=self.node_public_keys,
                                                             nodeIds=self.node_ids)
        return nodes_dto

    def getPublicRSAKey(self, request: minbft_client_manager_pb2.GetClientPublicRSAKeyMsg,
                        context: grpc.ServicerContext) -> minbft_client_manager_pb2.ClientPublicRSAKeyDTO:
        """
        Gets the public RSA key of the client

        :param request: the gRPC request
        :param context: the gRPC context
        :return: a PublicRSAKeyDTO with the key in PEM bytes
        """
        key_dto = minbft_client_manager_pb2.ClientPublicRSAKeyDTO(key=self.public_rsa_key.export_key(format="PEM"))
        return key_dto

    def setNodes(self, request: minbft_client_manager_pb2.ClientNodesDTO, context: grpc.ServicerContext) \
            -> minbft_client_manager_pb2.ClientNodesDTO:
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
        logging.info(f"Updated nodes configurations, ips: {self.node_ips}, ports: {self.node_ports}, "
                     f"ids: {self.node_ids}")
        return request

    def serviceRequest(self, request: minbft_client_manager_pb2.ClientServiceRequestMsg,
                       context: grpc.ServicerContext) -> minbft_client_manager_pb2.ClientAck:
        """
        Sends a service request to the replicated service

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        self.send_service_request(operation_data=request.operationData, operation_type=request.operationType)
        return minbft_client_manager_pb2.ClientAck()

    def serviceReply(self, request: minbft_client_manager_pb2.ClientServiceReplyMsg, context: grpc.ServicerContext) \
            -> minbft_client_manager_pb2.ClientAck:
        """
        Reply from a node that has committed

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        if request.sequenceNumber in self.committed_sequence_numbers:
            return minbft_client_manager_pb2.ClientAck()
        self.replies[request.sequenceNumber].append(request)
        if self.has_a_quorum_been_reached(sequence_number=request.sequenceNumber):
            self.accept(reply=request)
            logging.info(f"Client: {self.ip}, port: {self.port}, id: {self.id}, "
                         f"completed request: {request.sequenceNumber}")
            operation_type = random.randint(0, 1)
            operation_data = -1
            if operation_type == 1:
                operation_data = random.randint(0, 1000)
            self.send_service_request(operation_data=operation_data, operation_type=operation_type)
        return minbft_client_manager_pb2.ClientAck()

    def configure(self, request: minbft_client_manager_pb2.ConfigureClientMsg,
                  context: grpc.ServicerContext) -> minbft_client_manager_pb2.ClientAck:
        """
        Configures the client

        :param request: the gRPC request
        :param context: the gRPC context
        :return: An Ack
        """
        self.fault_threshold = request.faultThreshold
        self.resend_timeout_seconds = request.resendTimeout
        self.id = request.clientId
        return minbft_client_manager_pb2.ClientAck()


def serve(port: int = 50044, log_dir: str = "/", max_workers: int = 10,
          log_file_name: str = "minbft_client_manager.log") -> None:
    """
    Starts the gRPC server for managing clients

    :param port: the port that the server will listen to
    :param log_dir: the directory to write the log file
    :param log_file_name: the file name of the log
    :param max_workers: the maximum number of GRPC workers
    :return: None
    """
    constants.LOG_FILES.MINBFT_CLIENT_MANAGER_LOG_DIR = log_dir
    constants.LOG_FILES.MINBFT_CLIENT_MANAGER_LOG_FILE = log_file_name
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    minbft_client_manager_pb2_grpc.add_MinbftClientManagerServicer_to_server(MinbftClientManagerServicer(port=port),
                                                                             server)
    server.add_insecure_port(f'[::]:{port}')
    server.start()
    logging.info(f"MinBFT client started, listening on port: {port}")
    return server


# Program entrypoint
if __name__ == '__main__':
    ports = [9001]
    servers = list(map(lambda x: serve(port=x, log_dir="./"), ports))
    for server in servers:
        server.wait_for_termination()
