import urllib.request
import ipaddress

import socketserver
import socket
import ssl

import cgi
import xmlrpc.server
import xmlrpc.client




def HTTPrequest(url):
    '''
    Function used to get data from an url.
    Args:
        A URL
    '''

    with urllib.request.urlopen(url) as f:
        response = f.read()



class TCPRequestHandler(socketserver.BaseRequestHandler):
    '''
    General request handler for TCP server. Appends the incoming data into server memory.
    '''
    def handle(self):
        if self.server.timeout != 0:
            self.server.socket.settimeout(self.server.timeout)
        data = self.request.recv(1024).strip()
        self.server._storage.append("{} wrote:".format(self.client_address[0]) + str(data))
        self.request.sendall(bytes("Message received.\n", 'utf-8'))
            
    

class TCPServer(socketserver.TCPServer):
    '''
    Class to create a TCPServer
    
    Attributes:
        storage = [] A list to store incoming data from clients

    Methods:
        get_storage() = Returns the memory of the server
        attach_ssl() = Attaches a ssl certificate to the sockets of the server
        detach_ssl = Removes the ssl certificate from the sockets of the server
        start() = Starts the server in forever mode
    '''
    def __init__(self, server_address, port, requesthandler=TCPRequestHandler):
        self._storage = []
        socketserver.TCPServer.__init__(self, (server_address, port), requesthandler)

    def get_storage(self):
        return self._storage

    def attach_ssl(self, path_to_certchain, path_to_private_key):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(path_to_certchain, path_to_private_key)
        self.socket = context.wrap_socket(self.socket, server_side=True)

    def detach_ssl(self):
        try:
            self.socket = self.socket.detach()
        except:
            pass

    def start(self, timeout=None):
        if timeout != None:
            self.timeout = timeout
        try: 
            print("Server started. Listening on port {}".format(self.server_address[1]))
            self.serve_forever()
        except KeyboardInterrupt as e:
            print("\nServer switched off.")



class TCPClient:
    '''
    Class to create a TCP Client

    Attributes:
        sock = the socket through which the client communicates
        (host, port) = The hostname and port number to which(if) the client is connected to. 
        sslflag = Flag to show whether the client's socket is wrap with a ssl context
        
    Methods:
        connect_to_server() = Requires the host name and port number of the server. Establishes a connection between a running server if possible.
        attach_ssl() = Attaches a ssl certificate to the port of the client
        detach_ssl() = Detaches the ssl context if the socket is wrapped with it.
        send_data() = Sends data to a server if the socket is connected to it. Receives a response from the server.
    '''
    def __init__(self, host=None, port=None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port   
        self.sslflag = 0
        try:
            self.connect_to_server(self.host, self.port)
        except TypeError as e:
            pass
        

    def connect_to_server(self, host, port):
        try:
            self.host = host
            self.port = port
            self._sock.connect((self.host, self.port))

        except OSError:
            self.host = host
            self.post = port
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try: 
                self._sock.connect((self.host, self.port))
            except ConnectionRefusedError as e:
                return "Server doesn't exist"
            if self.sslflag == 1:
                self.attach_ssl()

    def attach_ssl(self):
        context = ssl.create_default_context()
        try: 
            self._sock = context.wrap_socket(self._sock, server_hostname=self.host)
            self.sslflag = 1
        except TypeError as e:
            pass

    def detach_ssl(self):
        try: 
            self.socket = self.socket.detach()
        except:
            pass
            
    def send_data(self, data):
        try:
            self._sock.sendall(bytes(data + '/n', "utf-8"))
            response = str(self._sock.recv(1024), "utf-8")
            self.connect_to_server(self.host, self.port)
            return response
        except OSError as e1:
            return "Client is not connected to server."




class UDPRequestHandler(socketserver.BaseRequestHandler):       
    '''
    General UDP Request Handler. Appends incoming data to the memory of the server.
    '''
    def handle(self):
        if self.server.timeout != None:
            self.server.socket.settimeout(self.server.timeout) 
        data, sock = self.request[0].strip(), self.request[1]
        self.server._storage.append("{} wrote:".format(self.client_address[0]) + str(data))
        sock.sendto(bytes("Message received.\n", "utf-8"), self.client_address)


class UDPServer(socketserver.UDPServer):
    '''
    Class to create a UDP Client.
    
    Attributes:
        storage = A list to store incoming data from clients

    Methods:
        get_storage = Returns the storage of the server.
        attach_ssl = Attaches SSL certificate and key to the socket of the server.
        detach_ssl = detaches the SSL certificate from the socket.
        start = starts the server in forever mode
    '''
    def __init__(self, server_address, port, requesthandler=UDPRequestHandler):
        self._storage = []
        socketserver.UDPServer.__init__(self, (server_address, port), requesthandler)
    
    def get_storage(self):
        return self._storage

    def attach_ssl(self, path_to_certchain, path_to_private_key):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(path_to_certain, path_to_private_key)
        self.socket = context.wrap_socket(self.socket, server_side=True)

    def detach_ssl(self):
        try:
            self.socket = self.socket.detach()
        except:
            pass
    def start(self, timeout=None):
        if timeout != None:
            self.timeout = timeout
        try: 
            print("Server started. Listening on port {}".format(self.server_address[1]))
            self.serve_forever()
        except KeyboardInterrupt as e:
            print("\nServer switched off.")


class UDPClient:
    '''
    Class to create a TCP Client

    Attributes:
        sock = the socket through which the client communicates
        (host, port) = The hostname and port number to which(if) the client is connected to. 
        sslflag = Flag to show whether the client's socket is wrap with a ssl context
        timeout = Sets the timeout of the sockets to check for unestablished connections.(Data may never reach any server)
        
    Methods:
        attach_ssl() = Attaches a ssl certificate to the port of the client
        detach_ssl() = Detaches the ssl context if the socket is wrapped with it.
        send_data() = Sends data to a server if the socket is connected to it. Receives a response from the server.
    '''
    def __init__(self, host=None, port=None, timeout=None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.host = host
        self.port = port
        self.sslflag = 0
        if timeout != None:
            self._sock.settimeout(timeout)

    def send_data(self, data, host=None, port=None):
        if host!= None and port != None:
            self.host = host
            self.port = port
        try:
            self._sock.sendto(bytes(data + '/n', "utf-8"), (self.host, self.port))
            response = str(self._sock.recv(1024), "utf-8")
            return response
        except TypeError:
            return "Specify the server to send data"
        except TimeoutError:
            return "Could'nt reach the server. Server may not exist."


    def attach_ssl(self):
        context = ssl.create_default_context()
        try: 
            self._sock = context.wrap_socket(self._sock, server_hostname=self.host)
            self.sslflag = 1
        except TypeError as e:
            pass

    def detach_ssl(self):
        try: 
            self.socket = self.socket.detach()
        except:
            pass

    


#class XMLRPCRequestHandler(xmlrpc.server.SimpleXMLRPCRequestHandler, xmlrpc.server.CGIXMLRPCRequestHandler):
#    rpc_paths = ('/RPC2',)


class XMLRPCServer(xmlrpc.server.SimpleXMLRPCServer):
    '''
    Class to create a XMLRPC Server
    
    Methods:
        start() = Starts the server in forever mode
        attach_function = attaches function to the server
        attach_instance = attachese functions to the server so that exposed methods can be used.
    '''
    def __init__(self, server_address, port, requesthandler=None):
        xmlrpc.server.SimpleXMLRPCServer.__init__(self, (server_address, port))
        self.register_introspection_functions()
        self.register_multicall_functions()
    
    def start(self, timeout=None):
        try:
            print("Server started. Listening on port {}".format(self.server_address[1]))
            self.serve_forever()
        except KeyboardInterrupt as e:
            print("\nServer switched off")

    def attach_function(self, func, name=None):
        if name == None:
            self.register_function(func)
        else:
            self.register_function(func, name)
    
    def attach_instance(self, instance):
        self.register_instance(instance)
        

class XMLRPCClient(xmlrpc.client.ServerProxy):
    '''
    A Class to create a XMLRPCClient.
    Attributes:
        host = the host to which the client is connected to.

    methods:
        connect_to_server = connects the client to server. Server's url and port is needed.
        get_function_list = Returns the list of accessible functions
    '''

    def __init__(self, host=None):
        self.host = host
        try:
            xmlrpc.client.ServerProxy.__init__(self, self.host)
        except OSError:
            pass
    def connect_to_server(self, host):
        self.host = host
        xmlrpc.client.ServerProxy.__init__(self, self.host)

    def get_functions_list(self):
        try:
            return self.system.listMethods()
        except TypeError:
            return "Client is not connected to a server"





def generateIPaddresses(ip):
    '''
    Generates ip addreses in range given by a CIDR network
    '''
    try:
        ips = ipaddress.ip_network(ip, strict = False).hosts()
        li = []
        for ip in ips:
            li.append(ip)
        return li
    except ValueError as e:
        print("IP address not valid")
        raise e
        
    

