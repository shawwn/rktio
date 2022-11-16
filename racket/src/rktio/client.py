import socket 
import sys 
import time
 
def run_unix_domain_socket_client(filepath): 
    """ Run "a Unix domain socket client """ 
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) 
     
    # Connect the socket to the path where the server is listening 
    server_address = filepath  
    print ("connecting to %s" % server_address) 
    sock.connect(server_address) 
     
    try: 
        while True:
            message = "This is the message.  This will be echoed back!" 
            print  ("Sending [%s]" %message) 
     
            sock.sendall(bytes(message, 'utf-8')) 
            # Comment out the above line and uncomment
            # the below line for Python 2.7. 
            # sock.sendall(message) 
     
            amount_received = 0 
            amount_expected = len(message) 
             
            while amount_received < amount_expected: 
                data = sock.recv(16) 
                if not data:
                  print("Server closed")
                  break
                if data:
                  amount_received += len(data) 
                  print("Received [%s]" % data) 
                else:
                  print("Received blank [%s]" % data) 
                  time.sleep(0.5)
     
    finally: 
        print ("Closing client") 
        sock.close() 
 
if __name__ == '__main__': 
    args = sys.argv[1:]
    filepath = args[0] if len(args) >= 1 else "/tmp/socket_test.s" 
    run_unix_domain_socket_client(filepath)
