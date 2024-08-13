import socket


def main():
    sock_udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_udp_client.sendto(bytes('This is a test hello_hello_hello', "utf-8"), ("127.0.0.1", 15000))
    print("message Sent!")
    msg_from_server = sock_udp_client.recvfrom(1024)
    print(msg_from_server)


if __name__ == "__main__":
    main()
