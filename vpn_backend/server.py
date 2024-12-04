import socket
from udp import receive as udp_receive

BIND_ADDR = ('127.0.0.10', 8888)

def run_server():
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    raw_socket.bind(BIND_ADDR)

    print(f"[*] Listening on {BIND_ADDR[0]}:{BIND_ADDR[1]}")

    while True:
        client_addr, request, valid = udp_receive(raw_socket, BIND_ADDR, 1024)

        if(not valid):
            print(f"[*] {request}")
        else:
            print(f"[*] {client_addr[0]}:{client_addr[1]} says: {request}")

    raw_socket.close()

    

if __name__ == "__main__":
    run_server()
    