#!/usr/bin/env python2
import base64
import hashlib
import hmac
import json
import subprocess
from urllib import urlencode

import time
from flask import Flask, session, redirect, url_for, request, render_template
import copy
import config
import notification
from flipdotuser import *
from LdapForm import *
import sys
reload(sys)
sys.setdefaultencoding('utf-8')


app = Flask(__name__)
if not app.debug:
    import logging
    from logging import FileHandler
    file_handler = FileHandler(config.LOG_FILE)
    file_handler.setLevel(logging.WARNING)
    app.logger.addHandler(file_handler)


@app.route('/')
def index():
    if 'username' in session:

        return redirect(url_for('user'))
    else:
        return render_template('login.html', username=None)


@app.route('/user', methods=['GET', 'POST'])
def user():
    form = LdapForm(request.form)
    try:
        dn, data = FlipdotUser().getuser(session['username'])
    except FrontendError as e:
        return render_template("error.html", message=e.message)

    if request.method == "POST" and request.form.get('submit', '') == 'submit':
        if not form.validate():
            return render_template('index.html', form=form)

        new = copy.deepcopy(data)

        new['sn'][0] = form.sammyNick.data.encode('utf8', 'ignore')
        new['uid'][0] = form.uid.data.encode('utf8', 'ignore')
        new.setdefault('mail', [''])[0] = (form.mail.data.encode('utf8', 'ignore'))

        new['sshPublicKey'] = [x.entry.data.encode('utf8', 'ignore') for x in form.sshKeys if len(x.entry.data) > 0]
        new['macAddress'] = [x.entry.data.encode('utf8', 'ignore') for x in form.macs if len(x.entry.data) > 0]

        meta = get_meta(data)
        meta['drink_notification'] = form.drink_notification.data
        meta_str = json.dumps(meta).encode('utf8', 'ignore')
        if not 'postOfficeBox' in new:
            new['postOfficeBox'] = [None]
        new['postOfficeBox'][0] = meta_str

        if form.password.data != '':
            old_pw = form.oldPassword.data.encode('utf8', 'ignore')
            new_pw = form.password.data.encode('utf8', 'ignore')
            print("update pw")
            FlipdotUser().setPasswd(dn, old_pw, new_pw)

        FlipdotUser().setuserdata(dn, data, new)

        return redirect(url_for('user'))

    elif request.method == "POST" and request.form.get('submit', '') == 'addSSH':
        e = ListSSHForm()
        e.entry = ""
        e.delete = False
        form.sshKeys.append_entry(e)
        return render_template('index.html', form=form)
    elif request.method == "POST" and request.form.get('submit', '') == 'addMAC':
        e = ListMacForm()
        e.entry = ""
        e.delete = False
        form.macs.append_entry(e)
        return render_template('index.html', form=form)
    elif request.method == "POST":
        remove_deleted_entry(form.sshKeys)
        remove_deleted_entry(form.macs)

        return render_template('index.html', form=form)

    form.uid.data = data['uid'][0]
    form.sammyNick.data = data['sn'][0]

    for key in data.get('sshPublicKey', []):
        e = ListSSHForm()
        e.entry = key
        e.delete = False
        form.sshKeys.append_entry(e)

    for addr in data.get('macAddress', []):
        e = ListMacForm()
        e.entry = addr
        e.delete = False
        form.macs.append_entry(e)

    form.mail.data = data.get('mail', [''])[0]
    form.password.data = ""
    form.oldPassword.data = ""
    form.confirm.data = ""

    meta = get_meta(data)
    form.drink_notification.data = meta['drink_notification']
    return render_template('index.html', form=form)

def get_meta(data):
    meta_str = data.get('postOfficeBox', [None])[0]
    meta = {
        "drink_notification": "instant",  # instant, daily, weekly, never
        "last_drink_notification": 0,
    }
    if meta_str:
        try:
            meta_o = json.loads(meta_str)
            if type(meta_o) == dict:
                meta = meta_o
        except:
            pass
    return meta

def remove_deleted_entry(form_list):
    tmp = []
    for x in range(0, len(form_list.data)):
        key = form_list.pop_entry()
        if not key.data['delete']:
            tmp.append(key)
    for x in tmp[::-1]:
        form_list.append_entry(x.data)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        uid = request.form.get('uid', '')
        pwd = request.form.get('password', '')
        try:
            valid, dn = FlipdotUser().login(uid, pwd)
        except FrontendError as e:
            return render_template("error.html", message=e.message)
        if valid:
            session['username'] = dn
        else:
            session.pop('username', None)
    elif request.method == 'GET' and request.args.get('token', ''):
        try:
            token = request.args.get('token')
            dn, date, digest = token.split('|')
            if float(date) + 60*60*24 < time.time():
                print "expired login token: %s" % (date, time.time())
                return render_template("error.html", message="Invalid login token")
            digest_raw = base64.decodestring(digest)
            dn_hmac = hmac.new(config.SECRET, dn+date, hashlib.sha256).digest()
            if hmac.compare_digest(dn_hmac, digest_raw):
                print 'success'
                session['username'] = dn
                session['logged_in_via'] = 'token'
                form = PasswdForm(request.form)
                form.password.data = ""
                form.confirm.data = ""
                return render_template('reset_password.html', username=dn, form=form)
            else:
                return render_template("error.html", message="Invalid login token")
        except Exception as e:
            logging.warn(e)
            print e
            pass
    return redirect(url_for('index'))

@app.route('/reset_password', methods=['POST'])
def reset_password():
    if session['logged_in_via'] != 'token' or not session['username']:
        session.clear()
        return render_template("error.html", message="invalid token")
    form = PasswdForm(request.form)
    if request.method == "POST":
        if not form.validate():
            return render_template('index.html', form=form)
        new_pw = form.password.data.encode('utf8', 'ignore')
        print("update pw")
        FlipdotUser().setPasswd(session['username'], None, new_pw)

    return redirect(url_for('user'))

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    message = "You might have gotten a mail."
    if request.method != 'POST':
        return redirect(url_for('index'))

    uid = request.form.get('uid', '')
    uid = ldap.filter.escape_filter_chars(uid)

    dn = 'cn=%s,ou=members,dc=flipdot,dc=org' % uid
    try:
        ret = FlipdotUser().getuser(dn)
        if not ret:
            return render_template("error.html", message="User %s not found" % uid)
        mail = ret[1]['mail'][0]
    except FrontendError as e:
        return render_template("error.html", message=e.message)
    if not mail:
        return render_template("error.html", message=e.message)
    print "Resetting password for %s (%s)" % (uid, mail)
    date = str(time.time())
    dn_hmac = hmac.new(config.SECRET, dn+date, hashlib.sha256).digest()
    dn_signed = dn + "|" + date + "|" + base64.encodestring(dn_hmac).strip()
    msg = "Mit diesem Link kannst du dich einloggen und dein Passwort aendern:\n" \
          "http://ldapapp.fd/login?%s\n" % urlencode({'token': dn_signed})
    notification.send_notification(mail,
                                   "[flipdot-noti] Passwort-Reset",
                                   msg)
    print msg
    return render_template("error.html", message=message)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/list')
def list():
    user_list = FlipdotUser().get_all_users()
    return render_template('list.html', users=user_list)


@app.route('/add', methods=['POST', 'GET'])
def add():
    form = LdapForm(request.form)
    if request.method == 'POST' and form.validate():
        FlipdotUser().createUser(form.uid.data.encode('utf8', 'ignore'),
                                 form.sammyNick.data.encode('utf8', 'ignore'),
                                 form.mail.data.encode('utf8', 'ignore'),
                                 form.password.data.encode('utf8', 'ignore'))
        return redirect(url_for('list'))

    return render_template('add.html', form=form)


def get(list, index, default=''):
    try:
        return list[index]
    except IndexError:
        return default

@app.route('/system/who_is_in_config')
def who_is_in_config():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    subprocess.check_output(['bash', '-c', 'cd '+dir_path+'/utils && ./macaddress.sh'])
    with open("/tmp/ldap_macs.sed", "r") as f:
        resp = f.read()
    return resp


if __name__ == '__main__':
    app.secret_key = config.SECRET
    app.run(port=config.PORT)


class Error(Exception):
    pass

class FrontendError(Error):

    def __init__(self, message):
        self.message = message

