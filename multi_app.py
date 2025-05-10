"""This module handles socket connections and Telegram notifications based on SMS data."""

import os
import socket
import requests
import smtplib
import select
import signal
import sys
import urllib.parse
from dotenv import load_dotenv
from threading import Thread
from termcolor import colored, cprint
import logging as logging
from logging.handlers import RotatingFileHandler
RESTART_THRESHOLD = 2
import time
import threading

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

#TODO move .env reading out of mail func
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

        # conn state
        self.conn_attempt = 2 # how many times base_tread must respawn
        self.conn_health = False  # health flag
        self.sock = None
        self.health_sock = None
        self.conn_state = 0

        # Added ping tracking variables
        self.ping_interval = 60  # seconds between pings
        self.ping_timeout = 30  # seconds to wait for pong
        self.ping_id = None
        self.ping_lock = threading.Lock()

#        self.waiting_for_pong = False
        # Thread management
#        self.base_thread = None
#        self.watchdog_thread = None

        self.base_thread: Optional[threading.Thread] = None
        self.health_thread: Optional[threading.Thread] =  None
        self.watchdog_thread: Optional[threading.Thread] = None
        self.running = threading.Event()  # Event to control thread execution
        self.shutdown_event = threading.Event()  # Event to signal shutdown
        self.shutdown_timeout = 5  # seconds to wait for threads to stop
        self.check_interval = 10  # seconds between checks by watchdog
    
    def _close_sockets(self) -> None:
        for sock in [self.sock, self.health_sock]:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    rprint("Socket was closed without error(s)")
                except Exception as e:
                    # Only log errors if not during shutdown
                    if not self.shutdown_event.is_set():
                        eprint("Close socket bad attempt for " + self.name + " with error: " + str(e))
                finally:
                # Ensure that socket is cleared up
                    self.sock = None
                    self.health_sock = None
            else:
                wprint("Empty socket so nothing to close here")

    def _close_health_socket(self) -> None:
        """Safely close the health socket connection"""
        if self.health_sock:
            try:
                self.health_sock.shutdown(socket.SHUT_RDWR)
                self.health_sock.close()
            except Exception:
                pass  # Ignore errors during shutdown
            finally:
                self.health_sock = None

    def _close_socket(self) -> None:
        """Safely close the main socket connection"""
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except Exception:
                pass  # Ignore errors during shutdown
            finally:
                self.sock = None

    def _receive_data(self, sock, timeout=30.0):
        """
        Receive data from the socket until a specific sequence is detected.
        """
        if not sock:
            wprint("a socket for " + self.name + " was already destroyed. _receive_data return None")
            return None
        buffer = []
        sock.settimeout(timeout)
        try:
            while True:
                # Use select with proper timeout handling
                data = sock.recv(1024)
                if not data:
                    break
                buffer.append(data)
                if b"\r\n\r\n" in data:
                    return b''.join(buffer).decode('utf-8')
        except socket.timeout:
            return None
        except Exception as e:
            eprint("Exception in _receive_data for " + self.name + ": " + str(e))
            return None

    def _send_ping(self):
        """
        Send a Ping request
        """
        if not self.sock or self.shutdown_event.is_set():
            return False
        try:
            # Generate unique ActionID
            self.ping_id = str(int(time.time()))
            ping_msg = (
                "Action: Ping\r\n"
                f"ActionID: {self.ping_id}\r\n"
                "\r\n"
            )
            self.sock.sendall(ping_msg.encode('utf-8'))
            with self.ping_lock:
                self.last_ping_time = time.time()
                self.current_ping_id = ping_id
            return True
        except Exception as e:
            eprint("Send ping to " + self.name + " failed with: " + str(e))
            return False

    def _handle_pong(self, response):
        """Check if response is a valid Pong for our last Ping"""
        if not response or not self.ping_id:
            return False

        # ! Validate the Pong response matches our Ping
        if (f"Pong" in response and
                f"ActionID: {self.ping_id}" in response):
            rprint("PoNG REceived for " + self.name)
            with self.ping_lock:
                self.last_pong_time = time.time()
                self.ping_id = None
                self.conn_state -= 1
                rprint("conn_state for " + self.name + " was decremented: " + str(self.conn_state))
#                self.conn_state = max(0, self.conn_state - 1)
            return True
        return False

#TODO discard this method(using it only once)
    def _login_to_server(self):
        """
        Login to the server using the provided credentials.
        """
        login_command = f"Action: Login\r\nUsername: {self.username}\r\nSecret: {self.password}\r\n\r\n"
        send_data(self.sock, login_command)
        return self._receive_data()

    def _health_mon(self):
        """Dedicated thread for Ping-Pong health checks"""
        while self.running.is_set() and not self.shutdown_event.is_set():
            # Reconnect health socket if needed
            if not self.health_sock:
                try:
                    self.health_sock = socket.create_connection(
                        (self.ip_address, self.port),
                        timeout=10
                    )
                    # Send login
                    login_msg = (
                        "Action: Login\r\n"
                        f"Username: {self.username}\r\n"
                        f"Secret: {self.password}\r\n"
                        "Events: off\r\n"
                        "\r\n"
                    )
                    self.health_sock.sendall(login_msg.encode('utf-8'))
                    response = self._receive_data(self.health_sock, 10.0)
                    if not response or "Response: Success" not in response:
                        raise general_error("Health login failed")
                except Exception as e:
                    eprint("Health connection failed for " + self.name + " with: " + str(e))
                    self._close_health_socket()
                    time.sleep(10)
                    continue

            # Send Ping
            if self.health_sock:
                try:
                    self.ping_id = str(int(time.time()))
                    ping_msg = (
                        "Action: Ping\r\n"
                        f"ActionID: {self.ping_id}\r\n"
                        "\r\n"
                    )
                    self.health_sock.sendall(ping_msg.encode('utf-8'))
                    with self.ping_lock:
                        self.conn_state += 1  # Increment on Ping send
                        rprint("conn_state for " + self.name + " was incremented: " + str(self.conn_state))
                except Exception as e:
                    eprint("Ping send failed for" + self.name + " with: " + str(e))
                    self._close_health_socket()
                    continue

                # Wait for Pong
                start_time = time.time()
                while (time.time() - start_time) < self.ping_timeout:
                    response = self._receive_data(self.health_sock, 1.0)
                    if response and f"ActionID: {self.ping_id}" in response:
                        with self.ping_lock:
                            self.conn_state -= 1  # Decrement on Pong receive
                            rprint("conn_state for " + self.name + " was decremented: " + str(self.conn_state))
                        break
                    if self.shutdown_event.is_set():
                        break
                    time.sleep(0.1)
                else:
                    eprint("Pong timeout for " + self.name)

            # Sleep until next ping
            for _ in range(int(self.ping_interval)):
                if self.shutdown_event.is_set():
                    break
                time.sleep(1)

    def _watchdog(self):
        """Monitor and restart threads as needed"""
        while self.running.is_set() and not self.shutdown_event.is_set():
            if self.conn_attempt == 0:
                print("Connection attempts to " + self.name + "reached their maximum")
                self.running.clear()
                self.shutdown_event.set()
#                self._close_sockets()

                break
            # Check connection health
            with self.ping_lock:
                if self.conn_state > RESTART_THRESHOLD:  # Threshold for unhealthy state
                    self.conn_health = True

            # Handle unhealthy state
            if self.conn_health:
                eprint(f"Unhealthy connection detected for {self.name}, restarting...")
                self._close_sockets()
                self.conn_health = False
                self.conn_state = 0

                # Restart threads
                if self.base_thread and self.base_thread.is_alive():
                    self.base_thread.join(timeout=1.0)
                if self.health_thread and self.health_thread.is_alive():
                    self.health_thread.join(timeout=1.0)

                self._start_threads()

            time.sleep(5)

    def _old_watchdog(self) -> None:
        """
        Monitor the base thread and socket/connection.
        """
        while self.running.is_set() and not self.shutdown_event.is_set():

            if not self.conn_attempt:
                break
            # Check if base thread is alive
            if not self.base_thread or not self.base_thread.is_alive():
                if self.shutdown_event.is_set():
                    break  # Do not restart during shutdown
                rprint("Base thread is not running, starting...")
                self._start_base_thread()
            # Check if we need to send a ping
            now = time.time()
            send_ping = False
            with self.ping_lock:
                time_since_last_ping = now - self.last_ping_time
                time_since_last_pong = now - self.last_pong_time
                if (time_since_last_ping >= self.ping_interval or
                        (self.current_ping_id and time_since_last_pong >= self.ping_timeout)):
                    send_ping = True

                # Check for ping timeout
                if self.ping_id and (now - self.last_ping_time > self.ping_timeout):
                    eprint("Ping timeout for " + self.name)
#                    self.conn_state += 1
                    self.ping_id = None

            if send_ping and not self.ping_id:
                if self._send_ping():
                    self.conn_state += 1
                    rprint("conn_state for " + self.name + " was incremented: " + str(self.conn_state))
                else:
                    eprint("Failed to send ping to " + self.name)

            # Check connection state
            if self.conn_state >= RESTART_THRESHOLD:
                eprint("Connection problems detected for " + self.name)
#                self._close_socket()
                time.sleep(10)  # Wait before reconnect
                continue
            else:
                rprint("threshold for " + self.name + " is not exceeded: " + str(self.conn_state))
            time.sleep(5)
            print("alive watchdog for " + self.name)

    def _start_threads(self):
        """Start 2 main threads"""
        if not self.running.is_set():
            return

        if not self.conn_attempt:
            wprint("connections attempts for " + self.name + " have reached their maximum")
            self._close_sockets()
            self.shutdown_event.set()  # Signal threads to stop
            self.running.clear()  # Clear the running flag
            return
        # Base thread (SMS processing)
        if not self.base_thread or not self.base_thread.is_alive():
            self.base_thread = threading.Thread(
                target=self._base_worker,
                name=f"{self.name}-Base",
                daemon=False
            )
            self.base_thread.start()

        # Health thread (Ping-Pong)
        if not self.health_thread or not self.health_thread.is_alive():
            self.health_thread = threading.Thread(
                target=self._health_mon,
                name=f"{self.name}-Health",
                daemon=False
            )
            self.health_thread.start()

    def _start_base_thread(self) -> None:
        if self.shutdown_event.wait(timeout=self.shutdown_timeout):
            return  # Don't start new threads during shutdown
        if self.base_thread and self.base_thread.is_alive():
            wprint("Base thread is already running")
            return
        if not self.conn_attempt:
            wprint("connections attempts for " + self.name + " have reached their maximum")
            self._close_sockets()
            self.shutdown_event.set()  # Signal threads to stop
            self.running.clear()  # Clear the running flag
            return
        self.base_thread = threading.Thread(
            target=self._base_worker,
            name=f"{self.name}-Base",
            daemon=False  
        )
        self.base_thread.start()
#        rprint("Base thread for " + self.name + " is started")

    def _start_health_thread(self) -> None:
        if self.shutdown_event.wait(timeout=self.shutdown_timeout):
            return  # Don't start new threads during shutdown
        if self.health_thread and self.health_thread.is_alive():
            wprint("Health thread is already running")
            return
        if not self.conn_attempt:
            wprint("connections attempts for " + self.name + " have reached their maximum")
            self._close_sockets()
            self.shutdown_event.set()  # Signal threads to stop
            self.running.clear()  # Clear the running flag
            return
        self.health_thread = threading.Thread(
            target=self._health_mon,
            name=f"{self.name}-Health",
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
            name=f"{self.name}-Watchdog",
            daemon=False  
        )
        self.watchdog_thread.start()
#        rprint("Watchdog thread for " + self.name + " is started")

    def start(self):
        """Start all gateway threads"""
        if self.running.is_set():
            return
        self.running.set()
        self.shutdown_event.clear()
        self._start_threads()

        # Start watchdog
        self.watchdog_thread = threading.Thread(
            target=self._watchdog,
            name=f"{self.name}-Watchdog",
            daemon=False
        )
        self.watchdog_thread.start()

    def old_start(self) -> None:
        if self.running.is_set():
            wprint("Thread for " + self.name + " is already running")
            return
        self.running.set()
        self.shutdown_event.clear()
        self._start_base_thread()
        self._start_health_thread()
        self._start_watchdog_thread()
        rprint("Threads for " + self.name + " have been started")

    def stop(self):
        """Graceful shutdown of all threads"""
        if not self.running.is_set():
            return

        self.running.clear()
        self.shutdown_event.set()
        self._close_sockets()

        for thread in [self.base_thread, self.health_thread, self.watchdog_thread]:
            if thread and thread.is_alive():
                thread.join(timeout=self.shutdown_timeout)

    def old_stop(self) -> None:
        if not self.running.is_set():
            wprint("We're not running, but trying to stop")
            return
        rprint("Initiating graceful shutdown...")
        self.shutdown_event.set()  # Signal threads to stop
        self.running.clear()  # Clear the running flag
#TODO remove extra exception hadling
        try:
            # Close socket first to interrupt any blocking operations
            self._close_sockets()
            # Wait for threads to finish (with shutdown_timeout)
            if self.base_thread and self.base_thread.is_alive():
                rprint("Waiting for base thread to stop...")
                self.base_thread.join(timeout=self.shutdown_timeout)
                if self.base_thread.is_alive():
                    wprint("Base thread did not stop gracefully")
            if self.health_thread and self.health_thread.is_alive():
                rprint("Waiting for health thread to stop...")
                self.health_thread.join(timeout=self.shutdown_timeout)
                if self.health_thread.is_alive():
                    wprint("Health thread did not stop gracefully")
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
#            self._close_sockets()
            self.base_thread = None
            self.watchdog_thread = None
            self.health_thread = None

    def _base_worker(self):
        """Main thread for processing SMS messages"""
        while self.running.is_set() and not self.shutdown_event.is_set():
            if not self.sock:
                try:
                    rprint("Connection attempt to " + self.name + " #" + str(self.conn_attempt))
                    self.conn_attempt -= 1
                    self.sock = socket.create_connection(
                        (self.ip_address, self.port),
                        timeout=10
                    )
                    # Send login
                    login_msg = (
                        "Action: Login\r\n"
                        f"Username: {self.username}\r\n"
                        f"Secret: {self.password}\r\n"
                        "Events: off\r\n"
                        "\r\n"
                    )
                    self.sock.sendall(login_msg.encode('utf-8'))
                    response = self._receive_data(self.sock, 10.0)
                    if not response or "Response: Success" not in response:
                        raise general_error("Main login failed")
                    else:
                        gprint("Login to " + self.name + " is successful")

                except Exception as e:
                    eprint("Main connection failed for" + self.name + " with: " + str(e))
                    self._close_socket()
                    time.sleep(10)
                    continue
            try:
                response = self._receive_data(self.sock, 60.0)
                if response and "ReceivedSMS" in response:
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
            except Exception as e:
                eprint("Error in base worker for: " + self.name + " : " + str(e))
                self._close_sockets()

    def _run(self):
        response = ""
        rprint("Connection attempt to " + self.name + " #" + str(self.conn_attempt))
        self.conn_attempt -= 1
        self.sock = create_connection(self.ip_address, self.port)
        if self.sock:
            if "Response: Success" in self._login_to_server():
                gprint("Login to " + self.name + " is successful")
        #        send_telegram_message(self.telegram_token, self.telegram_chat_id, "Start listening to " + self.name)
                rprint("Listening to " + self.name)
                while self.running.is_set() and not self.shutdown_event.is_set():
                    if self.sock:
                        try:
                            response = self._receive_data(self.sock, 10.0)
                            if response:
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
                            else:
                                wprint("unexpected response for " + self.name + " : " + str(response))
                        except Exception as e:
                            eprint("Exception when calling receive_data for " + self.name + " : " + str(e))
                            self._close_socket()
#                            time.sleep(10)
                            # TODO remove hardcode!
                    else:
                        eprint("Socket is empty")
            else:
                eprint("Login failed")
                self._close_socket()
        else:
            eprint("No socket for " + self.name)
#            self._close_socket()

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
