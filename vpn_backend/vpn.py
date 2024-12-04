import socket
import json
import threading
import ipaddress
from udp import build_packet
from udp import receive as udp_receive
from utils import invalidate_args, validate_input_ip, format_dict, write_log, is_subnet, refact_request

BIND_ADDR = ('127.1.1.1', 9999)

class VPN_Server:

    def __init__(self):
        users = 'users.json'
        with open(users, 'r') as users_file:
            self._users = json.load(users_file)
        
        ips = 'ips.json'
        with open(ips, 'r') as ips_file:
            self._ips = json.load(ips_file)

        vlans = 'vlans.json'
        with open(vlans, 'r') as vlans_file:
            self._vlans = json.load(vlans_file)

        restricted_users = 'restricted_users.json'
        with open(restricted_users, 'r') as restricted_users_file:
            self._restricted_users = json.load(restricted_users_file)

        restricted_vlans = 'restricted_vlans.json'
        with open(restricted_vlans, 'r') as restricted_vlans_file:
            self._restricted_vlans = json.load(restricted_vlans_file)

        self._threads = []
        self._stop_flag = threading.Event()


    def start_server(self):
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        raw_socket.bind(BIND_ADDR)

        write_log(f"[*] Server started")
        write_log(f'[*] Listening on {BIND_ADDR[0]}: {BIND_ADDR[1]}')

        try:
            while not self._stop_flag.is_set():
                _, request, valid = udp_receive(raw_socket, BIND_ADDR, 1024)

                # Exit in stop case
                if self._stop_flag.is_set():
                    break

                if not valid:
                    write_log(f'[*] {request}')
                    continue


                write_log(f'[*] ' + refact_request(request))


                # Analize input
                data = json.loads(request)

                user = data['user']
                password = data['password']
                message = data['message']
                target_addr = (data['target_ip'], int(data['target_port']))

                is_valid = VPN_Server._validate_user(self._users, user, password)
                if is_valid:
                    # Add new thread
                    thread = threading.Thread(target=self._handle_user, args=(raw_socket, user, message, target_addr))
                    self._threads.append(thread)
                    thread.start()

                else:  # Invalid user
                    write_log(f'[*] Invalid user: {user}')
                    continue

        finally:
            # Wait for all threads
            for thread in self._threads:
                thread.join()


    def stop_server(self):
        # Establecer la bandera de detención
        self._stop_flag.set()
        write_log(f"[*] Server stopped")


    def _handle_user(self, raw_socket, user, message, target_addr):

        # Check user restrictions
        if user in self._restricted_users:
            restricted_ips = self._restricted_users[user]

            # Requested ip
            requested_ip = target_addr[0]

            for ip in restricted_ips:
                if is_subnet(requested_ip, ip):
                    # Has no access
                    write_log(f"[*] User: {user} has no access to IP address: {requested_ip}, because is in {ip}")
                    return

        # Check VLAN restrictions
        user_vlan = self._vlans[user]
        if user_vlan in self._restricted_vlans:
            restricted_ips = self._restricted_vlans[user_vlan]

            # Requested ip
            requested_ip = target_addr[0]

            for ip in restricted_ips:
                if is_subnet(requested_ip, ip):
                    # Has no access
                    write_log(f"[*] VLAN: {user_vlan} has no access to IP address: {requested_ip}, because is in {ip}")
                    return


        # Logic for assigning new IP
        new_addr = (self._ips[user], 9999)

        write_log(f'[Client -> Server] {message}')

        # Crea socket del cliente vpn
        vpn_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        vpn_socket.bind(new_addr)

        # poner en hilo la espera del mensaje
        thread = threading.Thread(target=self._resend, args=(vpn_socket, target_addr, new_addr))
        thread.start()
        
        # Manda el mensaje al socket del cliente
        packet = build_packet(message, new_addr, BIND_ADDR)
        raw_socket.sendto(packet, new_addr)


    def _resend(self, vpn_socket, server_addr, vpn_client_addr):
        _, request, valid = udp_receive(vpn_socket, vpn_client_addr, 1024)

        if not valid:
            write_log(f'[*] {request}')
            return
        
        packet = build_packet(request, server_addr, vpn_client_addr)
        vpn_socket.sendto(packet, server_addr)
        vpn_socket.close()




    def _create_user(self, username, password, vlan):
        exists = username in self._users
        if exists:
            print("[*] This username already exists")
        else:
            # Update users DB
            self._users[username] = password
            with open('users.json', 'w') as users_file:
                json.dump(self._users, users_file)

            # Generate new ip
            last_ip = list(self._ips.values())[-1]
            ip_obj = ipaddress.ip_address(last_ip)
            new_ip = str(ip_obj + 1)

            # Update ips DB
            self._ips[username] = new_ip
            with open('ips.json', 'w') as ips_file:
                json.dump(self._ips, ips_file)

            # Update vlans DB
            self._vlans[username] = vlan
            with open('vlans.json', 'w') as vlans_file:
                json.dump(self._vlans, vlans_file)

            log =f"[*] User added succesfully\nIP: {new_ip}\nVLAN: {vlan}"
            print(log)
            write_log(log)

    def _restrict_user(self, user, ip):
        # Validate user
        if not user in self._users:
            log = "[*] User does not exist"
            print(log)
            write_log(log)
            return

        if user in self._restricted_users:  # User is restricted
            if not ip in self._restricted_users[user]: # Ip is not restricted
                self._restricted_users[user].append(ip)
        else:
            self._restricted_users[user] = [ip]
        
        log = "[*] User restricted succesfully"
        print(log)
        write_log(log)
        
        # Update DB
        with open('restricted_users.json', 'w') as restricted_users_file:
                json.dump(self._restricted_users, restricted_users_file)
        
    def _restrict_vlan(self, vlan, ip):
        if vlan in self._restricted_vlans: # VLAN is restricted
            if not ip in self._restricted_vlans[vlan]: # Ip is not restricted
                self._restricted_vlans[vlan].append(ip)
        else:
            self._restricted_vlans[vlan] = [ip]
        
        log = "[*] VLAN restricted succesfully"
        print(log)
        write_log(log)

        # Update DB
        with open('restricted_vlans.json', 'w') as restricted_vlans_file:
                json.dump(self._restricted_vlans, restricted_vlans_file)

    def list_users(self):
        users = format_dict(self._users)
        print(users)
    
    def list_ips(self):
        ips = format_dict(self._ips)
        print(ips)

    def list_vlans(self):
        vlans = format_dict(self._vlans)
        print(vlans)

    def list_users_restrictions(self):
        users_restrictions = format_dict(self._restricted_users)
        print(users_restrictions)

    def list_vlans_restrictions(self):
        vlans_restrictions = format_dict(self._restricted_vlans)
        print(vlans_restrictions)

    @staticmethod
    def _validate_user(users, user, password):
        return user in users and users[user] == password




if __name__ == "__main__":
    vpn = VPN_Server()

    while True:
        input_str = input("admin> ")

        splited_input = input_str.split()
        if len(splited_input) == 0:
            print("Invalid input")
            continue

        command = splited_input[0]

        if command == "exit":
            vpn.stop_server()
            break

        elif command == "start":
            vpn._stop_flag.clear()

            server_thread = threading.Thread(target=vpn.start_server)
            server_thread.start()

        elif command == "stop":
            vpn.stop_server()

        elif command == "create_user":
            # Validate args count
            args = len(splited_input)
            invalid_count = invalidate_args(args-1, 3)
            if invalid_count:
                continue

            _, username, password, vlan = splited_input

            vpn._create_user(username, password, vlan)

        elif command == "restrict_user":
            # Validate args count
            args = len(splited_input)
            invalid_count = invalidate_args(args-1, 2)
            if invalid_count:
                continue

            _, username, ip = splited_input

            # Validar ip
            valid_ip = validate_input_ip(ip)
            if not valid_ip:
                continue

            vpn._restrict_user(username, ip)

        elif command == "restrict_vlan":
            args = len(splited_input)
            invalid_count = invalidate_args(args-1, 2)
            if invalid_count:
                continue

            _, vlan, ip = splited_input

            # Validate ip
            valid_ip = validate_input_ip(ip)
            if not valid_ip:
                continue

            # Validate vlan
            if not vlan.isdigit():
                print("Invalid vlan")
                continue

            vpn._restrict_vlan(vlan, ip)
        
        elif command == "list_users":
            vpn.list_users()

        elif command == "list_ips":
            vpn.list_ips()

        elif command == "list_vlans":
            vpn.list_vlans()

        elif command == "list_users_restrictions":
            vpn.list_users_restrictions()

        elif command == "list_vlans_restrictions":
            vpn.list_vlans_restrictions()

        else:
            print("Command not found")
