import socket
import struct
import re
import threading

# Constants for the servers
SERVER_HOST = '127.0.0.1'

MESSAGE_SERVER_PORT = 31554
AUTH_SERVER_PORT = 31555
NOTIFICATION_SERVER_PORT = 31556

server_data = {
    "token": None,
    "descriptors": {},
    "user": None,
    "authCode": None,
    "exitCode": None,
}

def connect_tcp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, MESSAGE_SERVER_PORT))
    return sock

def send_tcp_message(sock, message, size=4096, expect_response = True):
    sock.sendall(message)
    if(expect_response):
        response = sock.recv(size)
        return response
    return None

def send_udp_message(host, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (host, port))
    response, _ = sock.recvfrom(4096)
    return response

def listen_for_notification(tcp_sock):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_HOST, NOTIFICATION_SERVER_PORT))
    while True:
        data, _ = sock.recvfrom(4096)
        if data:
            handle_notification(data, tcp_sock)
        else:
            break
    sock.close()


def create_hello_message(username):
    message_number = 50
    message_length = 2 + 4 + 32
    user_name = username.ljust(32).encode('ascii')  # 32 bytes, padded with spaces
    message = struct.pack('!H I 32s', message_number, message_length, user_name)
    return message

def parse_hello_response(response):
    # Unpack the fixed portion of the response
    message_number, message_length = struct.unpack('!HI', response[:6])
    token = response[6:16].decode('ascii').strip()

    server_data['token'] = token

    print(f"Message Number: {message_number}")
    print(f"Message Length: {message_length}")
    print(f"Token: {token}")

    # Calculate the number of descriptors
    descriptor_start = 16
    descriptor_length = 202  # 2 bytes for message number + 200 bytes for explanation

    while descriptor_start < message_length:
        descriptor = response[descriptor_start:descriptor_start + descriptor_length]
        msg_number, msg_explanation = struct.unpack('!H200s', descriptor)
        explanation = msg_explanation.decode('ascii').strip()

        # Extract the name from the explanation using regex
        match = re.search(r"Name:\s*([a-zA-Z0-9_]+)", explanation)
        if match:
            name = match.group(1)
            # Save the name as the key and the message number as the value
            server_data['descriptors'][name] = msg_number

        print(f"Message Descriptor Number: {msg_number}")
        print(f"Message Descriptor Explanation: {explanation}")

        descriptor_start += descriptor_length

def create_list_users_message(user_type=3, filter_name=""):
    message_number = server_data['descriptors']['ListUsers']
    message_length = 2 + 4 + 10 + 2 + 32
    token = server_data['token'].ljust(10).encode('ascii')
    filter_name = filter_name.ljust(32).encode('ascii')
    message = struct.pack('!HI10s32sh', message_number, message_length, token, filter_name, user_type)
    return message

def parse_list_users_response(response):
    message_number, message_length = struct.unpack('!HI', response[:6])
    user_type = struct.unpack('!H', response[6:8])[0]
    users_data = response[8:]

    users = []
    for i in range(0, len(users_data), 32):
        user = users_data[i:i + 32].decode('ascii').strip()

        if i == 2*32 and server_data['user'] is None:
            server_data['user'] = user

        users.append(user)

    print(f"Message Number: {message_number}")
    print(f"Message Length: {message_length}")
    print(f"User Type: {user_type}")
    print(f"Users: {', '.join(users)}")

def create_message_user_message(token, user_name, message):
    message_number = server_data['descriptors']['MessageUser']
    token = token.ljust(10).encode('ascii')
    user_name = user_name.ljust(32).encode('ascii')
    message = message.ljust(1024).encode('ascii')

    message_length = 2 + 4 + 10 + 32 + 1024
    message = struct.pack('!H I 10s 32s 1024s', message_number, message_length, token, user_name, message)

    return message

def parse_message_user_response(response):
    message_number, message_length = struct.unpack('!HI', response[:6])
    status = struct.unpack('!B', response[6:7])[0]

    status_message = "OK" if status == 0 else "Error"

    print(f"Message Number: {message_number}")
    print(f"Message Length: {message_length}")
    print(f"Status: {status_message}")

def create_authorization_message(token):
    message_number = 50  # Fixed value for authorization
    message_length = 2 + 10  # 2 bytes for message number + 10 bytes for token
    token = token.ljust(10).encode('ascii')  # Ensure token is 10 bytes, padded if necessary
    message = struct.pack('!H10s', message_number, token)
    return message

def send_authorization_request(token):
    authorization_message = create_authorization_message(token)
    response = send_udp_message(SERVER_HOST, AUTH_SERVER_PORT, authorization_message)
    return response

def parse_authorization_response(response):
    message_number, authorization_code = struct.unpack('!H10s', response)
    authorization_code = authorization_code.decode('ascii').strip()  # Decode and strip padding
    return authorization_code

def create_broadcast_message(token, authorization_code, message_content):
    message_number = server_data['descriptors']['Broadcast']
    message_length = 2 + 4 + 10 + 10 + 1024
    token = token.ljust(10).encode('ascii')
    authorization_code = authorization_code.ljust(10).encode('ascii')
    message_content = message_content.ljust(1024).encode('ascii')
    message = struct.pack('!H I 1024s 10s 10s', message_number, message_length, message_content, token, authorization_code)
    return message

def send_broadcast_request(tcp_sock, token, authorization_code, message_content):
    broadcast_message = create_broadcast_message(token, authorization_code, message_content)
    response = send_tcp_message(tcp_sock, broadcast_message)
    return response

def parse_broadcast_response(response):
    message_number, message_length = struct.unpack('!HI', response[:6])
    status = struct.unpack('!B', response[6:7])[0]
    status_message = "OK" if status == 0 else "Error"

    print(f"Message Number: {message_number}")
    print(f"Message Length: {message_length}")
    print(f"Status: {status_message}")

    return status

def create_exit_message(token, exit_code):
    message_number = 99
    message_length = 2 + 4 + 10 + 20  # 2 bytes for message number, 4 for length, 10 for token, 20 for exit code
    token = token.ljust(10).encode('ascii')  # Ensure the token is 10 bytes
    exit_code = exit_code.ljust(20).encode('ascii')  # Ensure the exit code is 20 bytes
    message = struct.pack('!HI10s20s', message_number, message_length, token, exit_code)
    return message

def handle_notification(data, tcp_sock):
    # Unpack the notification message
    notification_type, = struct.unpack('!H', data[:2])
    notification_payload = data[2:22].decode('ascii').strip()

    print(f"\n[Notification] Type: {notification_type}, Payload: {notification_payload}\n")

    server_data["exitCode"] = notification_payload

def send_exit_request(tcp_sock):
    # Create and send the exit message
    exit_message = create_exit_message(server_data['token'], server_data["exitCode"])
    # Assuming the exit request is sent over the TCP connection
    send_tcp_message(tcp_sock, exit_message, expect_response=False)
    # tcp_sock.close()
    print("Exit request sent to server.")



def main():
    # Step 1: Connect to TCP Messaging Server
    tcp_sock = connect_tcp_server()

    # Step 2: Start the notification listener in a separate thread
    notification_thread = threading.Thread(target=listen_for_notification, args=(tcp_sock,))
    notification_thread.daemon = True
    notification_thread.start()



    # Step 3: Send Hello
    print("\nSending Hello Message... \n")
    hello_message = create_hello_message("amir_kakon")
    response = send_tcp_message(tcp_sock, hello_message)
    parse_hello_response(response)
    print("\nHello Message Completed! \n")

    # Step 4: Send List Users Message
    print("\nSending List Users Message... \n")
    list_users_message = create_list_users_message()
    response = send_tcp_message(tcp_sock, list_users_message, 64008)
    res2 = tcp_sock.recv(4096)
    parse_list_users_response(response)
    parse_list_users_response(res2)
    print("\nList Users Message Completed! \n")

    # Step 5: Message User
    print(f"\nMessaging User {server_data['user']}... \n")
    message_user = create_message_user_message(server_data["token"], server_data['user'], "Hello World!")
    response = send_tcp_message(tcp_sock, message_user)
    parse_message_user_response(response)
    print("\nMessaging User Completed! \n")

    # Step 6: Authorization
    print("\nSending Authorization Request... \n")
    token = server_data['token']
    authorization_response = send_authorization_request(token)
    server_data["authCode"] = parse_authorization_response(authorization_response)
    print(f"Authorization Code: {server_data['authCode']}")
    print("\nAuthorization Request Completed! \n")

    # Step 7: Broadcasting
    print("\nSending Broadcast Message... \n")
    message_content = "Hello, this is a broadcast message!"  # Customize your message content
    broadcast_response = send_broadcast_request(tcp_sock, server_data['token'], server_data['authCode'], message_content)
    parse_broadcast_response(broadcast_response)
    print("\nBroadcast Message Completed! \n")

    print("\nSending exit request to server...\n")
    send_exit_request(tcp_sock)

    # Step 9: Close the TCP connection
    print("\nProgram ended.\n")

if __name__ == "__main__":
    main()
