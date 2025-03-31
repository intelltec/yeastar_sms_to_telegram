"""This module handles socket connections and Telegram notifications based on SMS data."""

import os
import socket
import requests
import smtplib
from dotenv import load_dotenv

load_dotenv()

import signal
import sys

def signal_handler(signal, frame):
    print(chr(8)+chr(8),end="") #filter uuot ^c symbols
    print("Listening is finished...")
    sys.exit(0)

def smtpcodes(code):
    switch = {
            422:"Recipient Mailbox Full",
            431:"Server out of space",
            447:"Timeout. Try reducing number of recipients",
            510:"One of the addresses in your TO, CC or BBC line doesn't exist. Check again your recipients' accounts and correct any possible misspelling.",
            511:"One of the addresses in your TO, CC or BBC line doesn't exist. Check again your recipients' accounts and correct any possible misspelling.",
            512:"Check again all your recipients' addresses: there will likely be an error in a domain name (like mail@domain.coom instead of mail@domain.com)",
            541:"Your message has been detected and labeled as spam. You must ask the recipient to whitelist you",
            554:"Your message has been detected and labeled as spam. You must ask the recipient to whitelist you",
            550:"Though it can be returned also by the recipient's firewall (or when the incoming server is down), the great majority of errors 550 simply tell that the recipient email address doesn't exist. You should contact the recipient otherwise and get the right address.",
            553:"Check all the addresses in the TO, CC and BCC field. There should be an error or a misspelling somewhere."
    }
    print(switch.get(code, "Unknown SMTP code error"))

def mailout(tomail, from_device, SMS, delivery_receipt = False):
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    server = os.getenv('EMAIL_SERVER')
    port = os.getenv('EMAIL_PORT')
    password = os.getenv('EMAIL_PASS')
    email = os.getenv('EMAIL_ADDR')
    msg = MIMEMultipart('alternative')
    msg['From'] = email
#    msg['Return-Receipt-To'] = service_email
    msg['Reply-To'] = email
    listtomail=tomail.split(",",1)
    if len(listtomail) == 1:
        msg['To'] = tomail
        recepients = tomail
    else:
        #TODO automate Cc list creation(2+ eddresses)
        msg['To'] = listtomail[0]
        msg['Cc'] = listtomail[1]
        recepients = tomail.split(",")
#    print("tomail",tomail)
    msg['Subject'] = from_device
    msg['Return-Path'] = email

    part = MIMEText(SMS, 'plain', 'utf-8')
    msg.attach(part)
    try:
        print("trying to connect")
        mail = smtplib.SMTP(server, port)
#        mail.set_debuglevel(1)
        mail.ehlo()
        mail.starttls()
        mail.login(email, password)
        mail.sendmail(email, recepients, msg.as_string())
        print('The mail to ' + tomail + ' was sent out successfully')
#    finally:
        mail.quit()
    except smtplib.SMTPException as err:
#        bot.send_message(CHAT, "Unable to send email!")
        error_code = err.smtp_code
        error_message = err.smtp_error
        smtpcodes(error_code)
        logger.error(error_code)
        logger.error(error_message)

def create_connection(ip, connection_port):
    """
    Create a TCP socket connection to the specified IP address and port.
    """
    connection_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection_sock.connect((ip, connection_port))
    return connection_sock

def send_data(connection_sock, data):
    """
    Send data through the socket.
    """
    connection_sock.sendall(data.encode('utf-8'))

def receive_data(connection_sock):
    """
    Receive data from the socket until a specific sequence is detected.
    """
    buffer = []
    signal.signal(signal.SIGINT, signal_handler)
    while True:
        data = connection_sock.recv(1024)
        if not data or b"\r\n\r\n" in data:
            buffer.append(data)
            break
        buffer.append(data)
    return b''.join(buffer).decode('utf-8')

def login_to_server(connection_sock, user_name, user_password):
    """
    Login to the server using the provided credentials.
    """
    login_command = f"Action: Login\r\nUsername: {user_name}\r\nSecret: {user_password}\r\n\r\n"
    send_data(connection_sock, login_command)
    return receive_data(connection_sock)

def send_telegram_message(token, chat_id, text):
    """
    Send a message to a Telegram chat via bot.
    """
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = {'chat_id': chat_id, 'text': text}
    response = requests.post(url, data=data, timeout=10)
#    print("Debug Telegram:", response.text)

def parse_sms_data(sms_data):
    """
    Parse the SMS data from server response.
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
    Format parsed SMS data into a Telegram-friendly message format.
    """
    formatted_message = (
        "📩 Получено СМС\n"
        f"👤 От: {sms_info.get('Sender', 'Unknown')}\n"
        f"⏰ Время: {sms_info.get('Recvtime', 'Unknown')}\n"
        f"📝 Содержимое: {sms_info.get('Content', 'No content')}"
    )
    return formatted_message

def listen_for_incoming_sms(connection_sock, token, chat_id):
    """
    Continuously listen for incoming SMS and send formatted notifications to Telegram.
    """
    print("Listening for incoming SMS...")
    while True:
        response = receive_data(connection_sock)
        if "ReceivedSMS" in response:
            print("Received SMS: ", response)
            sms_info = parse_sms_data(response)
            formatted_message = format_sms_for_telegram(sms_info)
            send_telegram_message(token, chat_id, formatted_message)
            try:
                #TODO move mail address to env or whatever
                mailout("......@gmail.com", "Name of device", formatted_message)
            except:
                print("mailout() has failed!")
                send_telegram_message(token, chat_id, "mailout() has failed!")

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
