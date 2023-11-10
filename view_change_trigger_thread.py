import grpc
import time
import threading
import minbft_manager_pb2
import minbft_manager_pb2_grpc


class ViewChangeTriggerThread(threading.Thread):
    """
    Thread that runs a timer for a view change trigger
    """

    def __init__(self, leader_timeout_seconds: int, node_ip: str, node_port: int, client_ip: str, client_port: int,
                 client_id: int, sequence_number: int) -> None:
        """
        Initializes the thread

        :param leader_timeout_seconds: timeout (seconds) until a view change should be triggered
        :param node_ip: the IP of the node
        :param node_port: the port of the node
        :param client_ip: the ip of the client request that is delayed
        :param client_port: the port of the client request that is delayed
        :param client_id: the id of the client request that is delayed
        :param sequence_number: the sequence number of the client request that is delayed
        """
        threading.Thread.__init__(self)
        self.leader_timeout_seconds = leader_timeout_seconds
        self.node_ip = node_ip
        self.node_port = node_port
        self.stopped = False
        self.client_ip = client_ip
        self.client_port = client_port
        self.client_id = client_id
        self.sequence_number = sequence_number

    def run(self) -> None:
        """
        Resends the request until the thread is stopped

        :return: None
        """
        time.sleep(self.leader_timeout_seconds)
        if not self.stopped:
            with grpc.insecure_channel(f"{self.node_ip}:{self.node_port}") as channel:
                stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                stub.triggerViewChange(minbft_manager_pb2.TriggerViewChangeMsg(
                    clientIp=self.client_ip, clientPort=self.client_port, clientId=self.client_id,
                    sequenceNumber=self.sequence_number
                ))
