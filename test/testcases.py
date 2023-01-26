import unittest
import sys
sys.path.append("../")
from src.APIpackage.module import *
import ipaddress

class TestTCP(unittest.TestCase):
    def setUp(self):
        self.server_address = "127.0.0.1"
        self.server_running_port1 = 9000
        self.server_running_port2 = 9005
        self.illegal_port = 9030
        self.client1 = TCPClient()

    def test_create_client_without_host_address(self):
        self.assertEqual(self.client1.send_data("DUMP"), "Client is not connected to server.")

    def test_connect_to_server_illegal_port(self):
        self.assertEqual(self.client1.connect_to_server(self.server_address, self.illegal_port), "Server doesn't exist")

    def test_connect_to_server_legal_port(self):
        self.client1.connect_to_server(self.server_address, self.server_running_port1)
        self.assertEqual(self.client1._sock.getpeername(), (self.server_address, self.server_running_port1))
    
    def test_change_connection_to_new_server(self):
        self.client1.connect_to_server(self.server_address, self.server_running_port2)
        self.assertEqual(self.client1._sock.getpeername(), (self.server_address, self.server_running_port2))

    def test_check_send_data(self):
        self.client1.connect_to_server(self.server_address, self.server_running_port2)
        self.assertEqual(self.client1.send_data("dataaa1"), "Message received.\n")

    def test_check_send_data_second_time(self):
        self.client1.connect_to_server(self.server_address, self.server_running_port2)
        self.assertEqual(self.client1.send_data("dataaa2"), "Message received.\n")

    def test_check_send_data_third_time(self):
        self.client1.connect_to_server(self.server_address, self.server_running_port2)
        self.assertEqual(self.client1.send_data("dataaa3"), "Message received.\n")

    def check_ssl_connection(self):
        pass




class TestUDP(unittest.TestCase):
    def setUp(self):
        self.server_address = "127.0.0.1"
        self.server_running_port1 = 9000
        self.server_running_port2 = 9005
        self.illegal_port = 9010
        self.client1 = UDPClient(timeout=5)
        self.client2 = UDPClient(self.server_address, self.server_running_port2, timeout=5)

    def test_send_data_without_specifying_host(self):
        self.assertEqual(self.client1.send_data("DUMP"), "Specify the server to send data")

    def test_send_data_illegal_server(self):
        self.assertEqual(self.client1.send_data("DUMP", self.server_address, self.illegal_port), "Could'nt reach the server. Server may not exist.")

    def test_check_send_data(self):
        self.assertEqual(self.client1.send_data("dataaa", self.server_address, self.server_running_port1), "Message received.\n")
    
    def test_check_send_data_with_initialization(self):
        self.assertEqual(self.client2.send_data("dataaa"), "Message received.\n")

    def check_ssl_connection(self):
        pass




class TestXMLRPC(unittest.TestCase):
    def setUp(self):
        self.client = XMLRPCClient()
        self.server_address = "http://localhost:10000"

    def test_connect_to_server(self):
        self.client.connect_to_server(self.server_address)

    def test_get_functions_list_when_not_connected(self):
        self.assertEqual(self.client.get_functions_list, "Client is not connected to server")
    
    def test_connect_to_server(self):
        self.client.connect_to_server(self.server_address)
        self.assertEqual(self.client.get_functions_list, ['add', 'subtract', 'system.listMethods', 'system.methodHelp', 'system.methodSignature', 'system.multicall'])


class TestIP(unittest.TestCase):

    def test_correct_generation_IPV4(self):
        self.assertEqual(generateIPaddresses("192.0.0.0/30"), [ipaddress.IPv4Address('192.0.0.1'), ipaddress.IPv4Address('192.0.0.2')])


class TestHTTP(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
