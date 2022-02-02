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
    msg = MIMEText(message,_charset='utf-8')

    fromMail = "flipdot-noti@vega.uberspace.de"

    msg['Subject'] = subject
    msg['From'] = fromMail
    msg['To'] = to_address

    if not 'MAIL_PW' in dir(config):
        print("Error: MAIL_PW not set")
        return
    s = smtplib.SMTP('vega.uberspace.de')
    s.connect(host='vega.uberspace.de', port=587)
    s.ehlo()
    s.starttls()
    s.login(user=fromMail, password=config.MAIL_PW)
    s.sendmail(fromMail, [to_address], msg.as_string())
    s.quit()
