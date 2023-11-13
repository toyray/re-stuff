from scapy.all import *

def get_packet_src_ip(packet):
    if IP in packet:
        return packet[IP].src
    return None

def get_packet_src_port(packet):
    if TCP in packet:
        return packet[TCP].sport
    return None

def get_packet_dest_ip(packet):
    if IP in packet:
        return packet[IP].dst
    return None

def get_packet_dest_port(packet):
    if TCP in packet:
        return packet[TCP].dport
    return None

def extract_reqs(pcap_file, client_ip, client_port, server_ip, server_port):
    scapy_cap = rdpcap(pcap_file)
    previous_direction = ""

    counters = {
            "client": 0,
            "server": 0,
            }
    counter = 0

    for packet in scapy_cap:

        #TODO: For diagnostics
        #print(packet.summary())
        #print(packet.show())
        if not TCP in packet:
            continue

        src_ip = get_packet_src_ip(packet)
        src_port = get_packet_src_port(packet)
        dest_ip = get_packet_dest_ip(packet)
        dest_port = get_packet_dest_port(packet)

        if src_ip == client_ip and src_port == client_port \
                and dest_ip == server_ip and dest_port == server_port:
                    current_direction = "client"
        elif src_ip == server_ip and src_port == server_port \
                and dest_ip == client_ip and dest_port == client_port:
                    current_direction = "server"
        else:
            # Not one of our IPs, continue to the next packet
            continue

        # Discard padding packets
        if type(packet.lastlayer()) is scapy.packet.Padding:
            continue

        data = bytes(packet[TCP].payload)
        # Discard empty packets
        if len(data) == 0:
            continue

        if current_direction != previous_direction:
            write_mode = "wb"
            counter += 1
            counters[current_direction] += 1
        else:
            write_mode = "ab"

        previous_direction = current_direction

        req_file = "req_%04d_%s.bin" % (counter,
                current_direction)
        with open(req_file, write_mode) as o:
            o.write(data)

    print("Total requests: %d, from client: %d, from server: %d" % \
            (counter, counters["client"], counters["server"]))

if __name__ == '__main__':
    # Length of sys.argv is 1 by default and contains script name
    if len(sys.argv) != 4:
        print("Required args: pcap_file client_ip:port server_ip:port")
        exit(1)

    pcap_file = sys.argv[1]
    client_ip, client_port = sys.argv[2].split(":")
    server_ip, server_port = sys.argv[3].split(":")
    server_port = int(server_port)
    client_port = int(client_port)
    print(f"PCAP file: {pcap_file}")
    print(f"Client IP: {client_ip} Port: {client_port}")
    print(f"Server IP: {server_ip} Port: {server_port}")

    extract_reqs(pcap_file, client_ip, client_port, server_ip, server_port)

    print("Done")
