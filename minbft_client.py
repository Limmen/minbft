import grpc
import minbft_client_manager_pb2
import minbft_client_manager_pb2_grpc
import minbft_manager_pb2
import minbft_manager_pb2_grpc
import query_minbft
import time

if __name__ == '__main__':
    ip = "130.237.6.34"
    leader_timeout_seconds = 30
    node_ports = [8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009]
    node_ips = [ip, ip, ip, ip, ip, ip, ip, ip, ip]
    node_ids = list(range(len(node_ips)))
    public_keys = []
    client_ports = [9001]
    client_ips = [ip]
    client_ids = list(range(len(client_ips)))
    client_public_keys = []
    f = 4
    checkpoint_period = 100
    client_resend_timeout = 5

    # Get clients public keys
    for i in range(len(client_ips)):
        with grpc.insecure_channel(f"{client_ips[i]}:{client_ports[i]}") as channel:
            stub = minbft_client_manager_pb2_grpc.MinbftClientManagerStub(channel)
            public_key_dto: minbft_client_manager_pb2.ClientPublicRSAKeyDTO = query_minbft.get_client_public_rsa_key(
                stub=stub)
            client_public_keys.append(public_key_dto.key)

    # Configure clients
    for i in range(len(client_ips)):
        with grpc.insecure_channel(f"{client_ips[i]}:{client_ports[i]}") as channel:
            stub = minbft_client_manager_pb2_grpc.MinbftClientManagerStub(channel)
            query_minbft.configure_client(stub=stub, fault_threshold=f, resend_timeout=client_resend_timeout,
                                          client_id=client_ids[i])

    # Configure clients on the nodes
    for port in node_ports:
        with grpc.insecure_channel(f"{ip}:{port}") as channel:
            stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
            clients_dto: minbft_manager_pb2.ClientsDTO = query_minbft.set_clients(
                stub=stub, client_ips=client_ips, client_ports=client_ports, client_ids=client_ids,
                public_keys=client_public_keys)

    # Get public keys
    for port in node_ports:
        with grpc.insecure_channel(f"{ip}:{port}") as channel:
            stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
            public_key_dto: minbft_manager_pb2.PublicRSAKeyDTO = query_minbft.get_public_rsa_key(stub=stub)
            public_keys.append(public_key_dto.key)

    # Configure nodes and keys
    for port in node_ports:
        with grpc.insecure_channel(f"{ip}:{port}") as channel:
            stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
            nodes_dto: minbft_manager_pb2.NodesDTO = \
                query_minbft.set_nodes(stub=stub, node_ips=node_ips, node_ports=node_ports, public_keys=public_keys,
                                       leader_timeout_seconds=leader_timeout_seconds, fault_threshold=f,
                                       node_ids=node_ids, checkpoint_period=checkpoint_period)

    # Configure nodes and keys for clients
    for port in client_ports:
        with grpc.insecure_channel(f"{ip}:{port}") as channel:
            stub = minbft_client_manager_pb2_grpc.MinbftClientManagerStub(channel)
            nodes_dto: minbft_client_manager_pb2.ClientNodesDTO = \
                query_minbft.set_nodes_clients(stub=stub, node_ips=node_ips, node_ports=node_ports,
                                               public_keys=public_keys, node_ids=node_ids)

    time.sleep(1)

    # Test service request
    for port in client_ports:
        with grpc.insecure_channel(f"{ip}:{port}") as channel:
            stub = minbft_client_manager_pb2_grpc.MinbftClientManagerStub(channel)
            client_service_request_msg = minbft_client_manager_pb2.ClientServiceRequestMsg(
                operationType=0,
                operationData=-1
            )
            stub.serviceRequest(client_service_request_msg)

    time.sleep(5)

    # Crash
    with grpc.insecure_channel(f"{ip}:{node_ports[0]}") as channel:
        stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
        query_minbft.crash(stub=stub, timeout=1)

    time.sleep(60)
    # Crash
    with grpc.insecure_channel(f"{ip}:{node_ports[1]}") as channel:
        stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
        query_minbft.crash(stub=stub, timeout=1)
    time.sleep(60)

    # Crash
    with grpc.insecure_channel(f"{ip}:{node_ports[5]}") as channel:
        stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
        query_minbft.crash(stub=stub, timeout=1)
