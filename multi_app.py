"""This module handles socket connections and Telegram notifications based on SMS data."""

import os
import socket
import requests
import smtplib
import signal
import sys
import urllib.parse
from dotenv import load_dotenv
from threading import Thread
from termcolor import colored, cprint
import logging as logging
from logging.handlers import RotatingFileHandler

load_dotenv()

me = os.path.basename(__file__).split('.')[0]

""" log setup """
logfile = me + '.log'
logfile = os.path.dirname(os.path.realpath(__file__)) + '/' + logfile
formatter = logging.Formatter('%(levelname)s %(asctime)s> %(message)s ', datefmt='%d-%b-%y %H:%M:%S')
#logging.getLogger('PIL').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

class general_error(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(colored(self.message,'light_red',attrs=[ "reverse"]))

""" some cprint wrappers """
def rprint(text):
    cprint(text,'light_grey')
    logger.debug(text)
def eprint(text):
    cprint(text,'light_red')
#    cprint(text,'grey','on_red',attrs=['dark'])
    logger.error(text)
def wprint(text):
    cprint(text,'light_yellow')
    logger.info(text)
def gprint(text):
    cprint(text,'light_green')
    logger.info(text)

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
        msg['To'] = listtomail[0]
        msg['Cc'] = listtomail[1]
        recepients = tomail.split(",")
    msg['Subject'] = from_device
    msg['Return-Path'] = email
    part = MIMEText(SMS, 'plain', 'utf-8')
    msg.attach(part)
    try:
        rprint("trying to connect")
        mail = smtplib.SMTP(server, port)
#        mail.set_debuglevel(1)
        mail.ehlo()
        mail.starttls()
        mail.login(email, password)
        mail.sendmail(email, recepients, msg.as_string())
        wprint('The mail to ' + tomail + ' was sent out successfully')
        mail.quit()
    except smtplib.SMTPException as err:
        error_code = err.smtp_code
        error_message = err.smtp_error
        smtpcodes(error_code)
        logger.error(error_code)
        logger.error(error_message)

def create_connection(ip, connection_port):
    """
    Create a TCP socket connection to the specified IP address and port.
    """
    retry_delay = 15
    connect_timeout = 15
    connection_sock = None
#TODO connection attempts!
    while connection_sock == None:
        try:
            connection_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if connection_sock != None:
                connection_sock.settimeout(connect_timeout)
                connection_sock.connect((ip, connection_port))
                connection_sock.settimeout(None)
                return connection_sock
            else: 
                eprint("Cannot create socket... Retrying in " + retry_delay + " seconds")
                time.sleep(retry_delay)
        except Exception as e:
            eprint("create_connection exception: " + str(e))
    return None

def send_data(connection_sock, data):
    """
    Send data through the socket.
    """
    connection_sock.sendall(data.encode('utf-8'))

def check_socket(sock: socket.socket) -> bool:
    try:
        data = sock.recv(16, socket.MSG_DONTWAIT | socket.MSG_PEEK)
        if len(data) == 0:
            gprint("socket is ok")
            return True
    except BlockingIOError:
        wprint("socket is open and reading from it would block")
        return False
    except ConnectionResetError:
        eprint("socket was closed for some other reason")
        return False
    except Exception as e:
        eprint("unexpected exception " + str(e))
        return False
    return False
    

import select


def send_telegram_message(token, chat_id, text):
    """
    Send a message to a Telegram chat via bot.
    """
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = {'chat_id': chat_id, 'text': text}
    response = requests.post(url, data=data, timeout=10)

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

def format_sms_for_telegram(sms_info, name):
    """
    Format parsed SMS data into a Telegram-friendly message format.
    """
    raw_msg = sms_info.get('Content', 'No content')
    dec_msg = urllib.parse.unquote_plus(raw_msg)
    formatted_message = (
        "📩 Получено СМС\n"
        f"👤 Для: {name}\n"
        f"👤 От: {sms_info.get('Sender', 'Unknown')}\n"
        f"⏰ Время: {sms_info.get('Recvtime', 'Unknown')}\n"
        f"📝 Содержимое: {dec_msg}"
    )
    return formatted_message

def signal_handler(signal, frame):
    print(chr(8)+chr(8),end="") #filter out ^C symbols
    rprint("Listening is finished...")
    global gw_num
    global gateways
    for i in range(gw_num):
        wprint("Shutting " + str(i+1) + " thread ")        
        gateways[i].stop()

signal.signal(signal.SIGINT, signal_handler)

#TODO use class or whatever instead of the long arg list
class vars: 
    def __init__(self, ip_address, port, username, name, password, telegram_token, telegram_chat_id, sendto_email):
        self.ip_address = ip_address
        self.port = int(port)
        self.username = username
        self.name = name
        self.password = password
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.sendto_email = sendto_email

RESTART_THRESHOLD = 2
import time
import threading

class ReadGW(Thread):
    def __init__(self, ip_address, port, username, name, password, telegram_token, telegram_chat_id, sendto_email):
        Thread.__init__(self)
        self.ip_address = ip_address
        self.port = int(port)
        self.username = username
        self.name = name
        self.password = password
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.sendto_email = sendto_email
        self.conn_attempt = 1 # how many times base_tread must respawn
        self.sock = None
#        self.conn_state = {"Ping": 0}
        self.conn_state = 0

        self.base_thread: Optional[threading.Thread] = None
        self.watchdog_thread: Optional[threading.Thread] = None
        self.running = threading.Event()  # Event to control thread execution
        self.shutdown_event = threading.Event()  # Event to signal shutdown
        self.shutdown_timeout = 5  # seconds to wait for threads to stop
        self.check_interval = 10  # seconds between checks by watchdog
    
    def _close_socket(self) -> None:
        if self.sock:
            try:
        #    check_socket(self.sock)
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                rprint("Socket was closed without error(s)")
            except Exception as e:
                eprint("Close socket bad attempt for " + self.name + " with error: " + str(e))
            finally:
                self.sock = None
        else:
            wprint("Empty socket so nothing to close here")

    def _receive_data(self):
        """
        Receive data from the socket until a specific sequence is detected.
        """
        buffer = []
#TODO hardcode!
#        while self.running.is_set() and not self.shutdown_event.is_set():
        while True:
            try:
                data = self.sock.recv(1024)
                if not data or b"\r\n\r\n" in data:
                    buffer.append(data)
                    break
                buffer.append(data)
            except Exception as e:
                eprint("exception in socket.recv() for " + self.name + " : " + str(e))
        return b''.join(buffer).decode('utf-8')

    def _login_to_server(self):
        """
        Login to the server using the provided credentials.
        """
        login_command = f"Action: Login\r\nUsername: {self.username}\r\nSecret: {self.password}\r\n\r\n"
        send_data(self.sock, login_command)
        return self._receive_data()

    def _watchdog(self) -> None:
        """
        Monitor the base thread and socket connection.
        Restart the base thread if it's not running or the connection is bad.
        """
        while self.running.is_set() and not self.shutdown_event.is_set():
            # Check if base thread is alive
            if not self.base_thread or not self.base_thread.is_alive():
                if self.shutdown_event.is_set():
                    break  # Do not restart during shutdown
                rprint("Base thread is not running, starting...")
                self._start_base_thread()
            
            # Check socket connection state
            if self.sock and not self.shutdown_event.is_set():
                try:
                    # Send a test byte 
                    self.sock.send(b'\x00')
                except sock.error:
                    if self.shutdown_event.is_set():
                        break  # Don't handle errors during shutdown
                    eprint("Socket connection test failed. Closing dead socket...")
                    self._close_socket()
                    # The base thread will handle reconnection
                    break

                print("Sending ping for " + self.name)
                data = f"Action: Ping\r\n\r\n"
                self.sock.sendall(data.encode('utf-8'))
#                self.conn_state["Ping"] = self.conn_state.get("Ping") + 1
                self.conn_state += 1
#TODO remove hardcode!
#                time.sleep(5)
#                if self.conn_state["Ping"] < RESTART_THRESHOLD:
                if self.conn_state < RESTART_THRESHOLD:
#                    print("threshold for " + self.name + " is not exceeded:" + str(self.conn_state["Ping"]))
                    print("threshold for " + self.name + " is not exceeded:" + str(self.conn_state))
                    time.sleep(self.check_interval)
                    return
                else:
                    eprint("confirmed lost connection to " + self.name)
                    rprint("Waiting before reconnect...")
    #TODO remove hardcode!
                    time.sleep(180)
                    self.conn_state = 0
                    self._close_socket()
            # sleep till another check either broke from while() or conventionally
            print("alive watchdog for " + self.name)
            time.sleep(self.check_interval)

    def _start_base_thread(self) -> None:
        if self.shutdown_event.wait(timeout=self.shutdown_timeout):
            return  # Don't start new threads during shutdown
        if self.base_thread and self.base_thread.is_alive():
            wprint("Base thread is already running")
            return
        if not self.conn_attempt:
            wprint("connections attempts for " + self.name + " have reached their maximum")
            self._close_socket()
            self.shutdown_event.set()  # Signal threads to stop
            self.running.clear()  # Clear the running flag
            return
        self.base_thread = threading.Thread(
            target=self._run,
            name="BaseThread",
            daemon=False  
        )
        self.base_thread.start()
#        rprint("Base thread for " + self.name + " is started")
    
    def _start_watchdog_thread(self) -> None:
        if self.shutdown_event.wait(timeout=self.shutdown_timeout):
            return  # Don't start new threads during shutdown
        if self.watchdog_thread and self.watchdog_thread.is_alive():
            wprint("Watchdog thread has already been running")
            return
        self.watchdog_thread = threading.Thread(
            target=self._watchdog,
            name="WatchdogThread",
            daemon=False  
        )
        self.watchdog_thread.start()
#        rprint("Watchdog thread for " + self.name + " is started")

    def start(self) -> None:
        if self.running.is_set():
            wprint("Thread for " + self.name + " is already running")
            return
        self.running.set()
        self.shutdown_event.clear()
        self._start_base_thread()
        self._start_watchdog_thread()
        rprint("Threads for " + self.name + " have been started")

    def stop(self) -> None:
        if not self.running.is_set():
            wprint("We're not running, but trying to stop")
            return
        rprint("Initiating graceful shutdown...")
        self.shutdown_event.set()  # Signal threads to stop
        self.running.clear()  # Clear the running flag
#TODO remove extra exception hadling
        try:
            # Close socket first to interrupt any blocking operations
            self._close_socket()
            # Wait for threads to finish (with shutdown_timeout)
            if self.base_thread and self.base_thread.is_alive():
                rprint("Waiting for base thread to stop...")
                self.base_thread.join(timeout=self.shutdown_timeout)
                if self.base_thread.is_alive():
                    wprint("Base thread did not stop gracefully")
            if self.watchdog_thread and self.watchdog_thread.is_alive():
                rprint("Waiting for watchdog thread to stop...")
                self.watchdog_thread.join(timeout=self.shutdown_timeout)
                if self.watchdog_thread.is_alive():
                    wprint("Watchdog thread did not stop gracefully")
            rprint("Shutdown for " + self.name + " thread has completed")
        except Exception as e:
            eprint("Error during shutdown: " + str(e))
        finally:
            # Ensure all resources are cleaned up
#            self._close_socket()
            self.base_thread = None
            self.watchdog_thread = None

#TODO rewrite with CONNECTION_ATTEMPTS = 3
    def _run(self):
        response = ""
        rprint("Connection attempt to " + self.name + " #" + str(self.conn_attempt))
        self.conn_attempt -= 1
        self.sock = create_connection(self.ip_address, self.port)
        if self.sock:
            if "Response: Success" in self._login_to_server():
                gprint("Login to " + self.name + " is successful")
        #        send_telegram_message(self.telegram_token, self.telegram_chat_id, "Start listening to " + self.name)
                while self.running.is_set():
                    rprint("Listening to " + self.name)
                    if self.sock:
                        try:
                            response = self._receive_data()
                        except Exception as e:
                            eprint("Exception when calling receive_data for " + self.name + " : " + str(e))
                            pass
                        if "ReceivedSMS" in response:
                            rprint("Received SMS: " + response)
                            sms_info = parse_sms_data(response)
                            formatted_message = format_sms_for_telegram(sms_info, self.name)
                            send_telegram_message(self.telegram_token, self.telegram_chat_id, formatted_message)
                            try:
                                print(formatted_message)
                            #    mailout(self.sendto_email, self.name, formatted_message)
                            except:
                                eprint("mailout() has failed!")
                                send_telegram_message(token, chat_id, "mailout() has failed!")
                        elif "Pong" in response:
                            print("pong received for " + self.name)
#TODO make ping-pong counter class property
#                            self.conn_state["Ping"] = self.conn_state.get("Ping") - 1
                            self.conn_state -= 1
                    else:
                        eprint("Socket is empty")
                        time.sleep(100)
            else:
                eprint("Login failed")
                self.sock.close()
        else:
            eprint("No socket for " + self.name)
        
sys.tracebacklimit = 0

if __name__ == '__main__':
    gprint(me + " has been started")
    envfile = os.path.dirname(os.path.realpath(__file__)) + '/.env'
    if not os.path.exists(envfile):
            text = "The .env file does not exist!"
            logger.error(text)
            raise general_error(text)
    rprint("Organizing logs...")
    logtype = os.getenv('LOG_TYPE')
    rotation_logging_handler = RotatingFileHandler(logfile, maxBytes=5000, backupCount=5)
    if logtype == "debug":
        logger.setLevel(logging.DEBUG)
        sys.stdout = open(os.devnull, 'w')
    elif logtype == "info":
        logger.setLevel(logging.INFO)
        if os.stat(logfile).st_size > 0:
            rotation_logging_handler.doRollover()
        sys.stdout = open(os.devnull, 'w')
    elif logtype == "error":
        logger.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(levelname)s %(asctime)s %(filename)s:%(lineno)s > %(message)s (%(funcName)s)', datefmt='%d-%b-%y %H:%M:%S')
        sys.stdout = open(os.devnull, 'w')
    elif logtype == "console":
        logger.setLevel(logging.CRITICAL)
    else:
        raise general_error("Inappropriate log level!") 
    rotation_logging_handler.setFormatter(formatter)
    logger.addHandler(rotation_logging_handler)
    
    ip_address = os.environ.get('TG100_HOST').split(',')
    port = os.environ.get('TG100_PORT').split(',')
    username = os.environ.get('TG100_USERNAME').split(',')
    name = os.environ.get('TG100_NAME').split(',')
    password = os.environ.get('TG100_PASSWORD').split(',')
    if len(set(map(len, (ip_address,port,username,name,password)))) != 1:
        text = "Gateways lists of IP,port etc are not equal in length. Lookup in .env"
        logger.error(text)
        raise general_error(text) 
    telegram_token = os.getenv('TG_TOKEN')
    telegram_chat_id = os.getenv('TG_CHAT_ID')
    sendto_email = os.getenv('SENDTO_EMAIL')
    rprint("ENV  has been imported successfully")
    global gw_num
    gw_num = len(ip_address)
    rprint("TG100 gateways to listen to: " + str(gw_num))
    global gateways
    gateways = []
    for i in range(gw_num):
        wprint("starting " + str(i+1) + " thread")
        gateways.append(ReadGW(ip_address[i],port[i],username[i],name[i],password[i],telegram_token,telegram_chat_id,sendto_email))
        gateways[i].start()
