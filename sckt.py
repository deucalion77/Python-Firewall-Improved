import socket
import threading

def create_receive_socket():
    """
    Creates a socket to receive raw packets on the specified interface.
    """
    s_receive = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    s_receive.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s_receive

def create_send_tcp_socket():

    #Creates a socket to send raw TCP packets.
    send_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    send_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    send_tcp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return send_tcp

def create_icmp_send_socket():
    
    #Creates a socket to send raw ICMP packets.
    send_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    send_icmp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    send_icmp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return send_icmp

def create_send_udp_socket():
    """
    Creates a socket to send raw UDP packets.
    """
    send_udp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    send_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    send_udp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return send_udp

def handle_protocol(protocol, data):
    """
    Handle the specific protocol in a separate thread.
    """
    if protocol == 1:  # ICMP
        send_icmp = create_send_icmp_socket()
        print("ICMP socket created")
        # Further processing logic for ICMP
    elif protocol == 6:  # TCP
        send_tcp = create_send_tcp_socket()
        print("TCP socket created")
        # Further processing logic for TCP
    elif protocol == 17:  # UDP
        send_udp = create_send_udp_socket()
        print("UDP socket created")
        # Further processing logic for UDP
    else:
        print(f"Protocol {protocol} not supported")

def main():
    """
    Main loop to receive packets and create threads for handling based on protocol.
    """
    s_receive = create_receive_socket()
    
    while True:
        try:
            bits = s_receive.recvfrom(65535)[0]
            # Assuming Ethernet and IPV4 classes are defined elsewhere.
            frame = Ethernet(bits[0:14])
            packet = IPV4(bits[14:])
            protocol = packet.PROTOCOL

            # Start a new thread for each protocol handler
            threading.Thread(target=handle_protocol, args=(protocol, bits)).start()

        except KeyboardInterrupt:
            print("Exiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()

