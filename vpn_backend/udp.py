import socket
import struct


def calculate_Checksum(pseudo_header, header, message):
    msg = pseudo_header + header + message

    if len(msg) % 2 != 0:
        msg += b'\x00'

    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i + 1])
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def build_packet(data, dest_addr, src_addr):
    src_ip, src_port = src_addr
    dest_ip, dest_port = dest_addr

    udp_length = 8 + len(data)

    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dest_ip), 0, socket.IPPROTO_UDP, udp_length)

    checksum = 0
    udp_header = struct.pack("!HHHH", src_port, dest_port, udp_length, checksum)

    # Calculate correct checksum
    checksum = calculate_Checksum(pseudo_header, udp_header, data.encode())

    udp_header_with_checksum = struct.pack('!HHHH', src_port, dest_port, udp_length, checksum)
    
    packet = udp_header_with_checksum + data.encode()

    return packet



def receive(socket_raw, own_addr, buffer_size):

    try:
        data, sender_addr = socket_raw.recvfrom(buffer_size)
    except Exception as e:
        print("Error during receive:", e)

    udp_header = data[20:28]
    
    src_port, dest_port, length, checksum = struct.unpack('!HHHH', udp_header)

    # Verify using checksum
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(sender_addr[0]), socket.inet_aton(own_addr[0]), 0, socket.IPPROTO_UDP, length)
    udp_0_header = udp_header[:6] + b'\x00\x00' + udp_header[8:]

    calculated_checksum = calculate_Checksum(pseudo_header, udp_0_header, data[28:])

    if(calculated_checksum != checksum):
        return (sender_addr[0], src_port), "Checksum error, packet discarted", False

    data_payload = data[28:].decode('utf-8')

    packet =  {
        'src_port': src_port,
        'dest_port': dest_port,
        'length': length,
        'checksum': checksum,
        'data': data_payload,
        'sender_addr': sender_addr
    }

    return (sender_addr[0], src_port), data_payload, True