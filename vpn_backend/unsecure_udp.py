import struct

def build_packet(data, dest_addr, src_addr):
    # Construir el encabezado UDP
    src_port = src_addr[1]
    dest_port = dest_addr[1]

    udp_length = 8 + len(data)  # Longitud del encabezado UDP y datos

    checksum = 0
    udp_header = struct.pack('!HHHH', src_port, dest_port, udp_length, checksum)
    paquete_udp = udp_header + data.encode('utf-8')  # Asumiendo datos como una cadena

    return paquete_udp



def udp_receive(socket_raw, buffer_size):

    data, sender_addr = socket_raw.recvfrom(buffer_size)

    # Analizar el encabezado
    ip_header_length = (data[0] & 0xF) * 4  # Longitud variable del encabezado IP
    udp_header = data[ip_header_length:ip_header_length + 8]
    
    # Analizar el encabezado UDP
    src_port, dest_port, length, checksum = struct.unpack('!HHHH', udp_header)

    # Extraer los datos
    data_payload = data[ip_header_length + 8:].decode('utf-8')

    packet =  {
        'puerto_origen': src_port,
        'puerto_destino': dest_port,
        'longitud': length,
        'checksum': checksum,
        'datos': data_payload,
        'direccion': sender_addr
    }

    return (sender_addr[0], src_port), data_payload, True