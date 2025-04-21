# SMS to Telegram Forwarder

## Overview
The "SMS to Telegram Forwarder" is a Python script designed to listen for incoming SMS messages through an GSM gateway (Testing Yeastar TG-100) and forward them to a specified Telegram chat. This solution is perfect for organizations and individuals who want to receive crucial notifications or alerts directly on Telegram, ensuring they don't miss important updates.

## Features
- Connects to an SMS gateway to receive incoming SMS messages.
- Beautifies SMS messages with emojis to enhance readability.
- Forwards messages to a specified Telegram chat or goup or channel.
- Easy configuration via an `.env` file to manage settings.
- *NEW* Multithreading app for collecting sms from unlimited number of gateways
- *NEW* Logging with info/error/debug levels

## Technologies
This project utilizes:
- **Python 3.9**: Main programming language.
- **Socket Programming**: For connecting and interacting with the SMS gateway.
- **Requests**: For sending messages to Telegram.
- **Python-dotenv**: For managing configuration variables through an `.env` file.
- **Threading**: Thread-based parallel execution of a few processes as an objects for the same class.

## Installation and Setup

### Clone the repository
```bash
sudo apt install python3-venv python3-pip
git clone https://github.com/intelltec/yeastar_sms_to_telegram.git
cd yeastar_sms_to_telegram
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
# single-threading app
python3 app.py 
# multi-threading app
python3 multiapp.py 
# 
```
### .ENV hints
- LOG_TYPE={info,debug,error,console}. Debug is the same as console but into logfile. 
- TG100_HOST - either one or many IPs of gateways divided by comma
- TG100_PORT, TG100_USERNAME, TG100_PASSWORD - same as previous, but for gateways' ports, usernames and passwords correspondingly
- TG100_NAME - inner names just to distinction of SMS<br>

Note: there'd be an exception if above so-declared arrays will have different lengths
