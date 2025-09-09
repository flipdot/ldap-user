# -*- coding:utf-8 -*-
import smtplib
import threading
from email.mime.text import MIMEText

import config


def send_notification_newthread(to_address, subject, message):
    send_thread = threading.Thread(
        target=send_notification,
        args=(to_address, subject, message)
    )
    send_thread.daemon = True
    send_thread.start()

def send_notification(to_address, subject, message):
    if not hasattr(config, 'MAIL_PASSWORD'):
        print("Error: MAIL_PASSWORD not set")
        return

    msg = MIMEText(message,_charset='utf-8')
    msg['Subject'] = subject
    msg['From'] = config.MAIL_FROM
    msg['To'] = to_address

    s = smtplib.SMTP(config.MAIL_HOST)
    s.connect(host=config.MAIL_HOST, port=config.MAIL_PORT)
    s.ehlo()
    s.starttls()
    s.login(user=config.MAIL_FROM, password=config.MAIL_PASSWORD)
    s.sendmail(config.MAIL_FROM, [to_address], msg.as_string())
    s.quit()
