from typing import List
import minbft_client_manager_pb2
import minbft_client_manager_pb2_grpc
import minbft_manager_pb2
import minbft_manager_pb2_grpc
import csle_collector.constants.constants as constants


def get_nodes(stub: minbft_manager_pb2_grpc.MinbftManagerStub, timeout=constants.GRPC.TIMEOUT_SECONDS) \
        -> minbft_manager_pb2.NodesDTO:
    """
    Queries the server for the current nodes configuration

    :param stub: the stub to send the remote gRPC to the server
    :param timeout: the GRPC timeout (seconds)
    :return: a NodesDTO with details about the nodes in the system
    """
    get_nodes_dto_msg = minbft_manager_pb2.GetNodesMsg()
    nodes_dto: minbft_manager_pb2.NodesDTO = stub.getNodes(get_nodes_dto_msg, timeout=timeout)
    return nodes_dto


def get_public_rsa_key(stub: minbft_manager_pb2_grpc.MinbftManagerStub, timeout=constants.GRPC.TIMEOUT_SECONDS) \
        -> minbft_manager_pb2.PublicRSAKeyDTO:
    """
    Queries the server for its public RSA key

    :param stub: the stub to send the remote gRPC to the server
    :param timeout: the GRPC timeout (seconds)
    :return: A DTO with the RSA key
    """
    get_public_rsa_key_msg = minbft_manager_pb2.GetPublicRSAKeyMsg()
    public_key_dto: minbft_manager_pb2.PublicRSAKeyDTO = stub.getPublicRSAKey(get_public_rsa_key_msg, timeout=timeout)
    return public_key_dto


def get_client_public_rsa_key(stub: minbft_client_manager_pb2_grpc.MinbftClientManagerStub,
                              timeout=constants.GRPC.TIMEOUT_SECONDS) -> minbft_client_manager_pb2.ClientPublicRSAKeyDTO:
    """
    Queries a client for its public RSA key

    :param stub: the stub to send the remote gRPC to the server
    :param timeout: the GRPC timeout (seconds)
    :return: A DTO with the RSA key
    """
    get_public_rsa_key_msg = minbft_client_manager_pb2.GetClientPublicRSAKeyMsg()
    public_key_dto: minbft_manager_pb2.ClientPublicRSAKeyDTO = stub.getPublicRSAKey(get_public_rsa_key_msg,
                                                                                    timeout=timeout)
    return public_key_dto


def set_nodes(stub: minbft_manager_pb2_grpc.MinbftManagerStub, node_ips: List[str], node_ports: List[int],
              node_ids: List[int], public_keys: List[bytes], leader_timeout_seconds: int, fault_threshold: int,
              checkpoint_period: int, timeout=constants.GRPC.TIMEOUT_SECONDS) -> minbft_manager_pb2.NodesDTO:
    """
    Updates the nodes configuration in the system

    :param stub: the stub to send the remote gRPC to the server
    :param node_ips: list of node ips
    :param node_ports: list of node ports
    :param node_ports: list of node ids
    :param public_keys: list of public keys
    :param checkpoint_period: the checkpoint period
    :param leader_timeout_seconds: the T_exec parameter of the MinBFT protocol
    :param fault_threshold: the f parameter of the MinBFT protocol
    :param timeout: the GRPC timeout (seconds)
    :return: the updated nodes configuration (a NodesDTO)
    """
    set_nodes_dto_msg = minbft_manager_pb2.NodesDTO(nodeIps=node_ips, nodePorts=node_ports, publicKeys=public_keys,
                                                    leaderTimeoutSeconds=leader_timeout_seconds,
                                                    faultThreshold=fault_threshold, nodeIds=node_ids,
                                                    checkpointPeriod=checkpoint_period)
    nodes_dto: minbft_manager_pb2.NodesDTO = stub.setNodes(set_nodes_dto_msg, timeout=timeout)
    return nodes_dto


def set_nodes_clients(stub: minbft_client_manager_pb2_grpc.MinbftClientManagerStub, node_ips: List[str],
                      node_ports: List[int], public_keys: List[bytes], node_ids: List[int],
                      timeout=constants.GRPC.TIMEOUT_SECONDS) \
        -> minbft_client_manager_pb2.ClientNodesDTO:
    """
    Updates the nodes configuration for a client

    :param stub: the stub to send the remote gRPC to the server
    :param node_ips: list of node ips
    :param node_ports: list of node ports
    :param node_ids: list of node ids
    :param public_keys: list of public keys
    :param timeout: the GRPC timeout (seconds)
    :return: the updated nodes configuration (a NodesDTO)
    """
    set_nodes_dto_msg = minbft_client_manager_pb2.ClientNodesDTO(nodeIps=node_ips, nodePorts=node_ports,
                                                                 publicKeys=public_keys, nodeIds=node_ids)
    nodes_dto: minbft_client_manager_pb2.ClientNodesDTO = stub.setNodes(set_nodes_dto_msg, timeout=timeout)
    return nodes_dto


def create_ui(stub: minbft_manager_pb2_grpc.MinbftManagerStub, message: str, timeout=constants.GRPC.TIMEOUT_SECONDS) \
        -> minbft_manager_pb2.USIGCertificateDTO:
    """
    Queries the server to create a USIG certificate for a given message

    :param stub: the stub to send the remote gRPC to the server
    :param message: the message to create a certificate for
    :param timeout: the GRPC timeout (seconds)
    :return: the new USIG certificate
    """
    create_ui_msg = minbft_manager_pb2.CreateUIMsg(message=message)
    usig_certificate_dto: minbft_manager_pb2.USIGCertificateDTO = stub.createUI(create_ui_msg, timeout=timeout)
    return usig_certificate_dto


def verify_ui(stub: minbft_manager_pb2_grpc.MinbftManagerStub, message: str, unique_identifier: id, signature: bytes,
              timeout=constants.GRPC.TIMEOUT_SECONDS) -> minbft_manager_pb2.UIVerificationDTO:
    """
    Queries the server to verify a USIG certificate

    :param stub: the stub to send the remote gRPC to the server
    :param message: the message of the USIG certificate to verify
    :param unique_identifier: the identifier of the USIG certificate to verify
    :param signature: the signature of the USIG certificate to verify
    :param timeout: the GRPC timeout (seconds)
    :return: a UIVerificationDTO with the verification result
    """
    verify_ui_msg = minbft_manager_pb2.USIGCertificateDTO(message=message, uniqueIdentifier=unique_identifier,
                                                          signature=signature)
    ui_verification_dto: minbft_manager_pb2.UIVerificationDTO = stub.verifyUI(verify_ui_msg, timeout=timeout)
    return ui_verification_dto


def compromise(stub: minbft_manager_pb2_grpc.MinbftManagerStub, timeout=constants.GRPC.TIMEOUT_SECONDS) \
        -> minbft_manager_pb2.CompromisedDTO:
    """
    Updates the compromise status of the node

    :param stub: the stub to send the remote gRPC to the server
    :param timeout: the GRPC timeout (seconds)
    :return: a CompromisedDTO with the compromise status of the node
    """
    compromise_msg = minbft_manager_pb2.CompromiseMsg()
    compromised_dto: minbft_manager_pb2.CompromisedDTO = stub.compromise(compromise_msg, timeout=timeout)
    return compromised_dto


def get_compromised_status(stub: minbft_manager_pb2_grpc.MinbftManagerStub, timeout=constants.GRPC.TIMEOUT_SECONDS) \
        -> minbft_manager_pb2.CompromisedDTO:
    """
    Gets the compromised status of the node

    :param stub: the stub to send the remote gRPC to the server
    :param timeout: the GRPC timeout (seconds)
    :return: a CompromisedDTO with the compromise status of the node
    """
    get_compromised_status_msg = minbft_manager_pb2.GetCompromisedStatusMsg()
    compromised_dto: minbft_manager_pb2.CompromisedDTO = stub.getCompromisedStatus(get_compromised_status_msg,
                                                                                   timeout=timeout)
    return compromised_dto


def get_clients(stub: minbft_manager_pb2_grpc.MinbftManagerStub, timeout=constants.GRPC.TIMEOUT_SECONDS) \
        -> minbft_manager_pb2.ClientsDTO:
    """
    Queries the server for the current clients configuration

    :param stub: the stub to send the remote gRPC to the server
    :param timeout: the GRPC timeout (seconds)
    :return: a ClientsDTO with details about the authenticated clients
    """
    get_clients_dto_msg = minbft_manager_pb2.GetClientsMsg()
    clients_dto: minbft_manager_pb2.ClientsDTO = stub.getClients(get_clients_dto_msg, timeout=timeout)
    return clients_dto


def set_clients(stub: minbft_manager_pb2_grpc.MinbftManagerStub,
              public_keys: List[bytes], client_ips: List[str], client_ports: List[int], client_ids: List[int],
                timeout=constants.GRPC.TIMEOUT_SECONDS) -> minbft_manager_pb2.ClientsDTO:
    """
    Updates the clients configuration in the system

    :param stub: the stub to send the remote gRPC to the server
    :param public_keys: list of public keys of the clients
    :param client_ips: list of client ips
    :param client_ports: list of client ports
    :param client_ids: list of client ids
    :param timeout: the GRPC timeout (seconds)
    :return: the updated clients configuration (a ClientsDTO)
    """
    set_clients_dto_msg = minbft_manager_pb2.ClientsDTO(clientPorts=client_ports, clientIps=client_ips,
                                                        publicKeys=public_keys, clientIds=client_ids)
    clients_dto: minbft_manager_pb2.ClientsDTO = stub.setClients(set_clients_dto_msg, timeout=timeout)
    return clients_dto


def service_request(stub: minbft_manager_pb2_grpc.MinbftManagerStub, client_ip: str, client_port: int,
                    client_id: int, sequence_number: int,
                    operation_type: int, operation_data: int, signature: bytes) -> None:
    """
    Sends a service request on behalf of a client

    :param stub: the stub to send the remote gRPC to the server
    :param client_ip: the IP of the client
    :param client_port: the port of the client
    :param sequence_number: the sequence number of the request
    :param client_id: the id of the client
    :param operation_type: the operation type
    :param operation_data: the data of the operation
    :param signature: the signature of the client
    :return: None
    """
    service_request_msg = minbft_manager_pb2.ServiceRequestMsg(clientIp=client_ip, clientPort=client_port,
                                                               clientId=client_id,
                                                               sequenceNumber=sequence_number,
                                                               operationType=operation_type,
                                                               operationData=operation_data, signature=signature)
    service_future = stub.serviceRequest.future(service_request_msg)
    service_future.result()


def configure_client(stub: minbft_client_manager_pb2_grpc.MinbftClientManagerStub, fault_threshold: int,
                     resend_timeout: int, client_id: int, timeout=constants.GRPC.TIMEOUT_SECONDS) \
        -> minbft_client_manager_pb2.ClientAck:
    """
    Configures a client

    :param stub: the stub to send the remote gRPC to the server
    :param fault_threshold: the fault threshold of the client
    :param client_id: the id of the client
    :param resend_timeout: the resend timeout of the client
    :param timeout: the GRPC timeout (seconds)
    :return: ClientAck
    """
    configureClientMsg = minbft_client_manager_pb2.ConfigureClientMsg(faultThreshold=fault_threshold,
                                                                      resendTimeout=resend_timeout,
                                                                      clientId=client_id)
    client_ack: minbft_client_manager_pb2.ClientAck = stub.configure(configureClientMsg, timeout=timeout)
    return client_ack


def crash(stub: minbft_manager_pb2_grpc.MinbftManagerStub, timeout=constants.GRPC.TIMEOUT_SECONDS) \
        -> minbft_manager_pb2.CrashedDTO:
    """
    Updates the crash status of the node

    :param stub: the stub to send the remote gRPC to the server
    :param timeout: the GRPC timeout (seconds)
    :return: a CrashedDTO with the crash status of the node
    """
    crash_msg = minbft_manager_pb2.CrashMsg()
    crashed_dto: minbft_manager_pb2.CrashedDTO = stub.crash(crash_msg, timeout=timeout)
    return crashed_dto


def get_crashed_status(stub: minbft_manager_pb2_grpc.MinbftManagerStub, timeout=constants.GRPC.TIMEOUT_SECONDS) \
        -> minbft_manager_pb2.CrashedDTO:
    """
    Gets the crashed status of the node

    :param stub: the stub to send the remote gRPC to the server
    :param timeout: the GRPC timeout (seconds)
    :return: a CrashedDTO with the crash status of the node
    """
    get_crashed_status_msg = minbft_manager_pb2.GetCrashedStatusMsg()
    crashed_dto: minbft_manager_pb2.CrashedDTO = stub.getCrashedStatus(get_crashed_status_msg, timeout=timeout)
    return crashed_dto