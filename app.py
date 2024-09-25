import os
import socket
import requests
from dotenv import load_dotenv

load_dotenv()

def create_connection(ip, port):
    """
    Create a socket connection to the specified IP and port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    return sock

def send_data(sock, data):
    """
    Send data to the socket.
    """
    sock.sendall(data.encode('utf-8'))

def receive_data(sock):
    """
    Receive data from the socket until '\r\n\r\n'.
    """
    buffer = []
    while True:
        data = sock.recv(1024)
        if not data or b"\r\n\r\n" in data:
            buffer.append(data)
            break
        buffer.append(data)
    return b''.join(buffer).decode('utf-8')

def login_to_server(sock, username, password):
    """
    Send login command to the server using socket.
    """
    login_command = f"Action: Login\r\nUsername: {username}\r\nSecret: {password}\r\n\r\n"
    send_data(sock, login_command)
    return receive_data(sock)

def send_telegram_message(token, chat_id, text):
    """
    Send a message to a specified Telegram chat using bot token.
    """
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = {'chat_id': chat_id, 'text': text}
    response = requests.post(url, data=data, timeout=10)
    print("Debug Telegram:", response.text)

def parse_sms_data(sms_data):
    """
    Parse SMS data from the response.
    """
    lines = sms_data.split('\r\n')
    sms_info = {}
    for line in lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            sms_info[key.strip()] = value.strip()
    return sms_info

def format_sms_for_telegram(sms_info):
    """
    Format SMS data into a user-friendly string for Telegram messaging.
    """
    formatted_message = (
        "📩 Received SMS\n"
        f"👤 From: {sms_info.get('Sender', 'Unknown')}\n"
        f"⏰ Time: {sms_info.get('Recvtime', 'Unknown')}\n"
        f"📡 SMS Center: {sms_info.get('Smsc', 'Unknown')}\n"
        f"📝 Content: {sms_info.get('Content', 'No content')}"
    )
    return formatted_message

def listen_for_incoming_sms(sock, token, chat_id):
    """
    Continuously listen for incoming SMS messages and send alerts to Telegram.
    """
    print("Listening for incoming SMS...")
    while True:
        response = receive_data(sock)
        if "ReceivedSMS" in response:
            print("Received SMS: ", response)
            sms_info = parse_sms_data(response)
            formatted_message = format_sms_for_telegram(sms_info)
            send_telegram_message(token, chat_id, formatted_message)

if __name__ == '__main__':
    ip_address = os.getenv('TG_HOST')
    port = int(os.getenv('TG_PORT'))
    username = os.getenv('TG_USERNAME')
    password = os.getenv('TG_PASSWORD')
    telegram_token = os.getenv('TG_TOKEN')
    telegram_chat_id = os.getenv('TG_CHAT_ID')

    sock = create_connection(ip_address, port)
    if "Response: Success" in login_to_server(sock, username, password):
        print("Login successful")
        send_telegram_message(telegram_token, telegram_chat_id, "Script TG100 Is Ready")
        listen_for_incoming_sms(sock, telegram_token, telegram_chat_id)
    else:
        print("Login failed")

    sock.close()
