import socket
import struct

IP = '127.0.0.1'
MESSAGE_PORT = 31554
AUTHORIZATION_PORT = 31555
NOTIFICATION_PORT = 31556

class MessagingClient:
    def __init__(self, messaging_server_address):
        self.messaging_server_address = messaging_server_address
        self.token = None  # Store the token after the Hello message response

        # Initialize the socket and connect it to the server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to server at {self.messaging_server_address}...")
        self.sock.connect(self.messaging_server_address)
        print("Connected successfully.")

    def create_hello_message(self, username):
        MESSAGE_NUMBER = 50
        MAX_NAME_LENGTH = 32

        # Format username
        username_formatted = username.replace(" ", "_").encode('utf-8')
        if len(username_formatted) > MAX_NAME_LENGTH:
            raise ValueError("User name exceeds 32 bytes after formatting.")
        username_padded = username_formatted.ljust(MAX_NAME_LENGTH, b'\x00')

        # Calculate message length
        message_length = 2 + 4 + MAX_NAME_LENGTH

        # Pack message
        message = struct.pack('!hi32s', MESSAGE_NUMBER, message_length, username_padded)
        return message

    def create_list_users_message(self, message_number, token, user_type=2, filter_by=""):
        MAX_FILTER_LENGTH = 32

        # Ensure the token is in bytes
        if isinstance(token, str):
            token = token.encode('utf-8')

        # Format the filter
        filter_formatted = filter_by.encode('utf-8')
        if len(filter_formatted) > MAX_FILTER_LENGTH:
            raise ValueError("Filter exceeds 32 bytes after formatting.")
        filter_padded = filter_formatted.ljust(MAX_FILTER_LENGTH, b'\x00')

        # Calculate message length
        message_length = 2 + 4 + 10 + 2 + MAX_FILTER_LENGTH

        # Pack message
        message = struct.pack('! h i 10s H 32s', message_number, message_length, token, user_type, filter_padded)
        return message

    def send_message(self, message):
        try:
            print("Sending message...")
            self.sock.sendall(message)
            print("Message sent, awaiting response...")
            response = self.receive_response(self.sock)
            return response
        except Exception as e:
            print("Error during communication:", e)
            return None

    def receive_response(self, sock):
        try:

            # Read header
            header = sock.recv(8)
            if len(header) < 8:
                raise ValueError("Incomplete header received")

            # Unpack the header
            message_number, message_length = struct.unpack('!hi', header[:6])
            user_type = struct.unpack('!H', header[6:])[0]

            # Receive user data
            remaining_length = message_length - 8
            users_data = sock.recv(remaining_length)

            print("Received users_data:", users_data)

            users = []
            while len(users_data) >= 32:
                user = users_data[:32].decode('utf-8').strip()
                users.append(user)
                users_data = users_data[32:]

            print("Users:", users)
            return {"message_number": message_number, "message_length": message_length, "user_type": user_type,
                    "users": users}
        except Exception as e:
            print("Error receiving response:", e)
            return None

    def send_hello(self, username):
        message = self.create_hello_message(username)
        response = self.send_message(message)
        return response

    def list_users(self, user_type=2, filter_by=""):
        if self.token is None:
            raise ValueError("Token not set. Please run send_hello first.")

        message_number = 50
        message = self.create_list_users_message(message_number, self.token, user_type, filter_by)
        response = self.send_message(message)
        return response

    def close_connection(self):
        print("Closing the socket connection.")
        self.sock.close()


if __name__ == "__main__":
    client = MessagingClient(messaging_server_address=(IP, MESSAGE_PORT))
    inp = "-1"

    while inp != "0":
        inp = input("\n\nEnter Request:\n\t1)Hello\n\t2)List Users\n\t0)Exit\n")

        if inp == "1":
            print("Sending Hello...")
            response = client.send_hello("amir kakon")
            print("Hello Response:", response)

        elif inp == "2":
            user_type_input = input("Enter User Type (1: Admin, 2: Member, 3: Members + Admins): ")
            filter_input = input("Enter filter for user names (optional): ")
            print("Listing Users...")
            response = client.list_users(int(user_type_input), filter_input)
            print("List Users Response:", response)

    client.close_connection()
    print("Exiting... Goodbye!")
