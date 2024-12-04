import socket
import json
from udp import build_packet
from utils import validate_input_ip, validate_input_port

CLIENT_ADDR = ('127.0.0.1', 0)
VPN_ADDR = ('127.1.1.1', 9999)

def run_client(user, password, server_ip, server_port):
    while True:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

        try:
            message = input("> ")

            if(message == 'exit'): 
                break
            
            data = {
                "user": user,
                "password": password,
                "message": message,
                "target_ip": server_ip,
                "target_port": server_port
            }

            json_string = json.dumps(data)

            packet = build_packet(json_string, VPN_ADDR, CLIENT_ADDR)
            raw_socket.sendto(packet, VPN_ADDR)


        except KeyboardInterrupt:
            pass
        finally:
            raw_socket.close()


if __name__ == "__main__":

    user = input("Enter user: ")
    password = input("Enter password: ")

    server_ip = input("Enter server ip: ")
    is_valid_ip = validate_input_ip(server_ip, False)
    if is_valid_ip:
        server_port = input("Enter server port: ")
        is_valid_port = validate_input_port(server_port)
        
    if is_valid_ip and is_valid_port:
        run_client(user, password, server_ip, server_port)