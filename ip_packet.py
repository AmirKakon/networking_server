import struct
import socket
from http_server import http_server

global ip_total_length

port_range_start = 15000
port_range_end = port_range_start + 100
reply_to_message = True

TAB_1 = '\t-'
TAB_2 = '\t\t-'
TAB_3 = '\t\t\t-'
TAB_4 = '\t\t\t\t-'


def main():
    ip_packet_number = 1
    ip_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    ip_socket.bind(('127.0.0.1', 15000))
    tcp_frame_num = 0
    while True:
        ip_packet_data, addr = ip_socket.recvfrom(65536)
        if socket.inet_ntoa(ip_packet_data[12:16]) != '127.0.0.1':
            continue
        (ip_header, src_port, dst_port) = struct.unpack('! 20s H H', ip_packet_data[:24])
        if not (port_range_start <= dst_port <= port_range_end):
            continue
        sender_address = (socket.inet_ntoa(ip_packet_data[12:16]), src_port)
        print_ip_header(ip_packet_number, src_port, ip_packet_data, ip_header)
        (_, _, _, proto, _, _, ip_total_length, data_wo_ip_header) = ipv4_packet_unstruct(ip_packet_data)
        ip_packet_number = ip_packet_number + 1
        if proto == 17:  # UDP
            print('UDP message')
            udp_segment_unstruct(data_wo_ip_header, sender_address)
            if reply_to_message:
                response = input(TAB_3 + "Input response to the client")
                sock_udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock_udp_server.sendto(bytes(response, "utf-8"), sender_address)
        elif proto == 6:  # TCP
            http_server('127.0.0.1', 15001)
            print('TCP message')
            tcp_frame_num = tcp_frame_num + 1
            print('TCP FRAME NUMBER' + str(tcp_frame_num))
            (src_port, dest_port, sequence, acknowledgment, flag_urg,
             flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,
             header_length, data) = tcp_segment_unstruct(data_wo_ip_header)
            print(TAB_1 + 'TCP Segment: ')
            print(("\n" + TAB_2).join([
                TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port),
                'Header length:' + str(header_length),
                'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment),
                'Flags:',
                TAB_1 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin),
                'Data length w/o ip header and tcp header =' + str(ip_total_length - header_length - 20),
                'TCP Options data (in TCP header after 20 first bytes:',
                str(data),
                'Data after header :',
                str(data[header_length:]),
            ]))
        elif proto == 1:  # ICMP
            print('ICMP message')
        else:
            print(TAB_3 + data_wo_ip_header)


def ipv4_packet_unstruct(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ip_total_length, = struct.unpack('! H', data[2:4])
    ttl, proto, ipv4_src, ipv4_dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    str_ipv4_src = map(str, ipv4_src)
    ipv4_src = '.'.join(str_ipv4_src)
    str_ipv4_dest = map(str, ipv4_dest)
    ipv4_dest = '.'.join(str_ipv4_dest)

    return version, header_length, ttl, proto, ipv4_src, ipv4_dest, ip_total_length, data[header_length:]


def print_ip_header(ip_packet_number, src_port, ip_packet_data, ip_header):
    (
    version, header_length, ttl, proto, ipv4_src, ipv4_dest, ip_total_length, data_wo_ip_header) = ipv4_packet_unstruct(ip_packet_data)
    print(("\n" + TAB_1).join([
        'ip packet number = ' + str(ip_packet_number),
        'sender address: ip = ' + ipv4_src + ' port = ' + str(src_port),
        'packet total length = ' + str(ip_total_length),
        'packet content = ' + " ".join([str(element) for element in list(ip_packet_data)]),
        'ip header content = ' + " ".join([str(element) for element in list(ip_header)]),
        'ip packet decoded = ' + str(ipv4_packet_unstruct(ip_packet_data)),
        'source ip = ' + socket.inet_ntoa(ip_packet_data[12:16]),
        'dest ip =' + socket.inet_ntoa(ip_packet_data[16:20]),
        'IPv4 Packet additional fields: ',
        TAB_2 + 'IP Version: ' + format(version) + ', Header Length: ' + format(header_length) + ' TTL:' + format(ttl),
        TAB_2 + 'Protocol: {}'.format(proto, ipv4_src, ipv4_dest),
    ]))
    return ip_total_length


def tcp_segment_unstruct(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! HHLLH', data[:14])
    header_length = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, header_length, data[20:]


def udp_segment_unstruct(data, sender_address):
    src_port, dest_port, length = struct.unpack('! HH H', data[:6])
    data_without_udp_header = data[8:]
    # return src_port, dest_port, size, data_without_udp_header
    print(("\n" + TAB_2).join([
        'UDP Segment:',
        TAB_1 + 'Source Port {}, Destination Port: {}, UPD segment Length: {}'.format(src_port, dest_port, length),
        TAB_1+ 'Sending to: {}'.format(sender_address),
        TAB_1 + 'Data w/o udp header: {}'.format(data_without_udp_header),
    ]))


if __name__ == "__main__":
    main()
