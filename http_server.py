import socket
from datetime import datetime


def http_server(host = '127.0.0.1', port = 15001):
    http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http_socket.bind((host, port))
    http_socket.listen(5)

    print(f"[+] HTTP server Listening on {host}:{port}")

    conn_socket, conn_address = http_socket.accept()
    timestamp = datetime.now().strftime('%a %b %d %H:%M:%S %Y')
    print(f"[+] Accepting request from {conn_address[0]}:{conn_address[1]} ({timestamp})")

    request = conn_socket.recv(1024)
    print(f"[+] Received {request.splitlines()[0]}")

    # HTML content
    html_content = '''<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>A simple webpage</title>
        </head>
        <body>
            <h1>Simple HTML webpage</h1>
            <p>Hello, world, new!</p>
        </body>
        </html>'''

    # HTTP response headers and body
    http_response = f"""HTTP/1.1 200 OK
    Content-Length: 55743
    Content-Type: text/html; charset=utf-8
    Connection: keep-alive
    Cache-Control: s-maxage=300, public, max-age=0
    Content-Language: en-US
    Date: Thu, 06 Dec 2018 17:37:18 GMT
    ETag: "2e77ad1dc6ab0b53a2996dfd4653c1c3"
    Server: meinheld/0.6.1
    Strict-Transport-Security: max-age=63072000
    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY
    X-XSS-Protection: 1; mode=block
    Vary: Accept-Encoding,Cookie
    Age: 7
        \r\n
        {html_content}"""

    conn_socket.sendall(http_response.encode())
    print(f"[+] Sending HTTP response to {conn_address[0]}:{conn_address[1]}")

    conn_socket.close()
    http_socket.close()

