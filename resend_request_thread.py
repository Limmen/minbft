import logging
from typing import List
import grpc
import time
import threading
import minbft_manager_pb2
import minbft_manager_pb2_grpc


class ResendRequestThread(threading.Thread):
    """
    Thread for periodically resending a request until it has been committed
    """

    def __init__(self, service_request_msg: minbft_manager_pb2.ServiceRequestMsg, node_ips: List[str],
                 node_ports: List[int], timeout_seconds: int) -> None:
        """
        Initializes the thread

        :param service_request_msg: the service request message
        :param node_ips: the list of node IPs
        :param node_ports: the list of node ports
        :param timeout_seconds: the timeout period for resends
        """
        threading.Thread.__init__(self)
        self.service_request_msg = service_request_msg
        self.node_ips = node_ips
        self.node_ports = node_ports
        self.stopped = False
        self.timeout_seconds = timeout_seconds

    def run(self) -> None:
        """
        Resends the request until the thread is stopped

        :return: None
        """
        while not self.stopped:
            for i in range(len(self.node_ips)):
                try:
                    with grpc.insecure_channel(f"{self.node_ips[i]}:{self.node_ports[i]}") as channel:
                        stub = minbft_manager_pb2_grpc.MinbftManagerStub(channel)
                        stub.serviceRequest(self.service_request_msg)
                except:
                    pass
            time.sleep(self.timeout_seconds)
