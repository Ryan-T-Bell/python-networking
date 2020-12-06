import socket
import struct
import sys
import array


# AF_INET (default), AF_INET6, AF_UNIX
# SOCK_STREAM, SOCK_DGRAM, SOCK_RAW
# IPROTO_RAW

class IpHeader:

    def __init__(self, src_ip, dst_ip):
        self.ip_ver_ihl = 69
        self.ip_tos = 0
        self.ip_len = 0
        self.ip_id = 1984
        self.ip_frag = 0
        self.ip_ttl = 64
        self.ip_proto = 16
        self.ip_check = 0
        self.ip_saddr = socket.inet_aton(src_ip)
        self.ip_daddr = socket.inet_aton(dst_ip)

    def set_ip_header(self, src_ip, dst_ip):
        self.ip_ver_ihl = 69        # Putting decimal conversion of 0x45 for Version and Internet Header Length
        self.ip_tos = 0             # 96 for capture the flag
        self.ip_len = 0
        self.ip_id = 1984
        self.ip_frag = 0            # Set fragmentation to off
        self.ip_ttl = 64            # Time to Load
        self.ip_proto = 16          # 16=CHAOS
        self.ip_check = 0           # kernel will fill the correct checksum
        self.ip_saddr = socket.inet_aton(src_ip)
        self.ip_daddr = socket.inet_aton(dst_ip)

    def set_ip_header_for_tcp(self, src_ip, dst_ip):
        self.ip_ver_ihl = 69        # Putting decimal conversion of 0x45 for Version and Internet Header Length
        self.ip_tos = 0             # 96 for capture the flag
        self.ip_len = 0
        self.ip_id = 1984
        self.ip_frag = 0            # Set fragmentation to off
        self.ip_ttl = 64            # Time to Load
        self.ip_proto = 6           # 6=TCP
        self.ip_check = 0           # kernel will fill the correct checksum
        self.ip_saddr = socket.inet_aton(src_ip)
        self.ip_daddr = socket.inet_aton(dst_ip)

    def pack_ip_header(self):
        return struct.pack('!BBHHHBBH4s4s', self.ip_ver_ihl, self.ip_tos, self.ip_len, self.ip_id, self.ip_frag,
                           self.ip_ttl, self.ip_proto, self.ip_check, self.ip_saddr, self.ip_daddr)

    def send_message(self, msg, dst_ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        packet = self.pack_ip_header() + msg
        s.sendto(packet, (dst_ip, 0))

class TcpHeader:
    '''
    To calculate the TCP segment header’s checksum field, a 12-byte TCP
    pseudo header is constructed and placed before the TCP segment.
    The TCP pseudo header consists of source address (4 bytes from IP header),
    destination address (4 bytes from IP header), reserved (1 byte), protocol
    (1 byte from IP header), tcp segment length (2 bytes computed from tcp header and data)
    '''
    def __init__(self):
        self.tcp_src = 54321                 # Source port
        self.tcp_dst = 7777                  # Destination port
        self.tcp_seq = 454                   # Sequence number
        self.tcp_ack_seq = 0                 # tc ack sequence number
        self.tcp_data_off = 5                # Data offset
        self.tcp_reserve = 0                 # The 3 reserve bits + ns flag in reserve field
        self.tcp_win = socket.htons(5840)    # Maximum allowed window size reordered to network order
        self.tcp_chck = 0                    # TCP checksum which will be calculated later on
        self.tcp_urg_ptr = 0                 # Urgent pointer only if urg flag is set

        # Combine the left shifted 4 bit tcp offset and the reserve field
        self.tcp_off_res = (self.tcp_data_off << 4) + self.tcp_reserve

        # TCP flags by bit starting from right to left
        self.tcp_fin = 0                     # Finished
        self.tcp_syn = 0                     # Synchronization
        self.tcp_rst = 0                     # Reset
        self.tcp_psh = 0                     # Push
        self.tcp_ack = 0                     # Acknowledgement
        self.tcp_urg = 0                     # Urgent
        self.tcp_ece = 0                     # Explicit Congestion Notification Echo
        self.tcp_cwr = 0                     # Congestion Window Reduced

    def build_tcp_flags(self):
        return self.tcp_fin + (self.tcp_syn << 1) + (self.tcp_rst << 2) + (self.tcp_psh << 3) + \
                    (self.tcp_ack << 4) + (self.tcp_urg << 5) + (self.tcp_ece << 6) + (self.tcp_cwr << 7)

    def pack_tcp_header(self):
        return struct.pack('!HHLLBBHHH', self.tcp_src, self.tcp_dst, self.tcp_seq, self.tcp_ack_seq, self.tcp_off_res,
                           self.tcp_flags, self.tcp_win, self.tcp_chck, self.tcp_urg_ptr)

    @staticmethod
    def pseudo_tcp_header(src_ip, dst_ip, tcp_header, user_data):
        src_address = socket.inet_aton(src_ip)
        dst_address = socket.inet_aton(dst_ip)
        reserved = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(user_data)

        ps_header = struct.pack('!4s4sBBH', src_address, dst_address, reserved, protocol, tcp_length)
        return ps_header + tcp_header + user_data

    @staticmethod
    def check_sum(pseudo_header):
        if len(pseudo_header) % 2 != 0:
            pseudo_header += b'\0'
        res = sum(array.array("H", pseudo_header))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16
        return (~res) & 0xffff


    def build_tcp_ip_packet(self, src_ip, dst_ip, user_data):

        # 1. Build IP Header
        ip = IpHeader
        ip.set_ip_header_for_tcp(src_ip, dst_ip)
        ip_header = ip.pack_ip_header()

        # 2. Build TCP Header
        pseudo_header = TcpHeader.pseudo_tcp_header(src_ip, dst_ip, tcp_header, user_data)
        tcp_check = TcpHeader.check_sum(pseudo_header)

        tcp_header = struct.pack('!HHLLBBH', self.tcp_src, self.tcp_dst, self.tcp_seq, self.tcp_ack_seq, self.tcp_off_res,
                              self.tcp_flags, self.tcp_win) + struct.pack('H', tcp_check) + struct.pack('H', self.tcp_urg_ptr)

        # Combine all of the headers and the user data
        packet = ip_header + tcp_header + user_data

    def send_message(self, msg, dst_ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        packet = self.pack_ip_header() + msg
        s.sendto(packet, (dst_ip, 0))

