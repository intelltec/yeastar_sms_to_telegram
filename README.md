# SMS to Telegram Forwarder

## Overview
The "SMS to Telegram Forwarder" is a Python script designed to listen for incoming SMS messages through an SMS gateway and forward them to a specified Telegram chat. This solution is perfect for organizations and individuals who want to receive crucial notifications or alerts directly on Telegram, ensuring they don't miss important updates.

## Features
- Connects to an SMS gateway to receive incoming SMS messages.
- Beautifies SMS messages with emojis to enhance readability.
- Forwards messages to a specified Telegram chat.
- Easy configuration via an `.env` file to manage settings.

## Technologies
This project utilizes:
- **Python 3.9**: Main programming language.
- **Socket Programming**: For connecting and interacting with the SMS gateway.
- **Requests**: For sending messages to Telegram.
- **Python-dotenv**: For managing configuration variables through an `.env` file.

## Installation and Setup

### Clone the repository
```bash
apt-get install python3-venv python3-pip
git clone https://github.com/roysbike/yeastar_sms_to_telegram.git
cd yeastar_sms_to_telegram
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 app.py
