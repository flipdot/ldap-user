#!/bin/sh
# coding: utf8
"exec" "`dirname $0`/.env/bin/python" "$0" "$@"

import base64
import hashlib
import hmac
import time
from urllib.parse import urlencode

import config
from flipdot_error import FrontendError
import logging

from flask import Flask, session, redirect, url_for, request, render_template, \
    Response

import ldap3
from ldap3.core.exceptions import LDAPException

import notification
from LdapForm import LdapForm, ListSSHForm, ListMacForm, ListRFIDForm, PasswdForm
from flipdotuser import FlipdotUser, Connection
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

sentry_sdk.init(
    dsn=config.SENTRY_DSN,
    integrations=[FlaskIntegration()]
)

app = Flask(__name__)


app = Flask(__name__)
app.secret_key = config.SECRET

logger = logging.getLogger(__name__)

@app.route("/error")
def error():
    logger.error("Test error was triggered")
    return "Error triggered, checkout your monitoring"

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('user'))
    else:
        return render_template('login.html', username=None)


@app.route('/user', methods=['GET', 'POST'])
def user():
    form = LdapForm(request.form)
    if 'username' not in session:
        return redirect(url_for('index'))
    fd = FlipdotUser()
    fd.login(session['username'], session['password'])
    data = fd.getuser(session['username'])

    if request.method == "POST" and request.form.get('submit', '') == 'submit':
        if not form.validate():
            return render_template('index.html', form=form, user=data)

        new_values = {
            "sn": form.sammyNick.data,
            "uid": form.uid.data,
            "mail": form.mail.data,
            "sshPublicKey": [x.entry.data for x in form.sshKeys if len(x.entry.data) > 0],
            "macAddress": [x.entry.data for x in form.macs if len(x.entry.data) > 0],
            "rfid": [x.entry.data for x in form.rfid if len(x.entry.data) > 0],
            "drinksNotification": form.drink_notification.data,
        }

        # data['sn'][0] = form.sammyNick.data.encode('utf8', 'ignore')
        # data['uid'][0] = form.uid.data
        # data.setdefault('mail', [''])[0] = (form.mail.data.encode('utf8', 'ignore'))
        #
        # data['sshPublicKey'] = [x.entry.data.encode('utf8', 'ignore') for x in form.sshKeys if len(x.entry.data) > 0]
        # data['macAddress'] = [x.entry.data.encode('utf8', 'ignore') for x in form.macs if len(x.entry.data) > 0]
        #
        # data['meta']['drink_notification'] = form.drink_notification.data

        if form.password.data != '':
            old_pw = form.oldPassword.data.encode('utf8', 'ignore')
            new_pw = form.password.data.encode('utf8', 'ignore')
            print("update pw")
            fd.setPasswd(data['dn'], old_pw, new_pw)
            session['password'] = new_pw

        fd.setuserdata(data['dn'], new_values)

        return redirect(url_for('user'))

    elif request.method == "POST" and request.form.get('submit', '') == 'addSSH':
        e = ListSSHForm()
        e.entry = ""
        e.delete = False
        form.sshKeys.append_entry(e)
        return render_template('index.html', form=form, user=data)
    elif request.method == "POST" and request.form.get('submit', '') == 'addMAC':
        e = ListMacForm()
        e.entry = ""
        e.delete = False
        form.macs.append_entry(e)
        return render_template('index.html', form=form, user=data)
    elif request.method == "POST" and request.form.get('submit', '') == 'addTAG':
        e = ListRFIDForm()
        e.entry = ""
        e.delete = False
        form.rfid.append_entry(e)
        return render_template('index.html', form=form, user=data)
    elif request.method == "POST":
        remove_deleted_entry(form.sshKeys)
        remove_deleted_entry(form.macs)
        remove_deleted_entry(form.rfid)

        return render_template('index.html', form=form, user=data)

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

    for tag in data.get('rfid', []):
        e = ListRFIDForm()
        e.entry = tag
        e.delete = False
        form.rfid.append_entry(e)


    form.mail.data = data.get('mail', [''])[0]
    form.password.data = ""
    form.oldPassword.data = ""
    form.confirm.data = ""

    form.drink_notification.data = data.get('drinksNotification', 'instant')
    return render_template('index.html', form=form, user=data)


@app.route('/user/set_member', methods=['POST'])
def set_admin():
    user_uid = request.form.get('uid')
    is_member = request.form.get('is_member')
    is_admin = request.form.get('is_admin')
    fd = FlipdotUser()
    fd.login(session['username'], session['password'])
    if user_uid is None or (is_member is None and is_admin is None):
        return render_template("error.html", message="must supply uid and is_member/is_admin")
    admin_data = fd.getuser(session['username'])
    user_data = fd.getuser(user_uid)

    if 'is_admin' not in admin_data['meta'] or not admin_data['meta']['is_admin']:
        return render_template("error.html", message="You must be admin")
    if is_member is not None:
        user_data['meta']['is_member'] = is_member == 'true'
        user_data['isFlipdotMember'] = is_member == 'true'
    if is_admin is not None:
        user_data['meta']['is_admin'] = is_admin == 'true'
    fd.setuserdata(user_data['dn'], user_data)
    return redirect(url_for('list'))


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
        if not uid or not pwd:
            return redirect("/", 302)
        fd = FlipdotUser()
        valid = fd.login(uid, pwd)
        if valid:
            session['username'] = uid
            session['password'] = pwd
        else:
            session.pop('username', None)
            session.pop('password', None)
    elif request.method == 'GET' and request.args.get('token', ''):
        try:
            token = request.args.get('token')
            dn, date, digest = token.split('|')
            if float(date) + 60 * 60 * 24 < time.time():
                print(f"expired login token: {float(date)} {time.time()}")
                return render_template("error.html", message="Invalid login token")
            digest_raw = base64.b64decode(digest.encode())
            dn_hmac = hmac.new(config.SECRET.encode(), (dn + date).encode(), hashlib.sha256).digest()
            if hmac.compare_digest(dn_hmac, digest_raw):
                print('success')
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
            print(e)
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
    if request.method != 'POST':
        return redirect(url_for('index'))

    uid = request.form.get('uid', '')
    uid = ldap3.filter.escape_filter_chars(uid)

    fd = get_anonymous()
    ret = fd.getuser(uid)
    if not ret:
        return render_template("error.html", message="User %s not found" % uid)
    mail = ret[1]['mail'][0]
    if not mail:
        return render_template("error.html", message="No email address found")
    print(f"Resetting password for {uid} {mail}")
    date = str(time.time())

    dn = config.LDAP_USER_DN.format(uid)
    dn_hmac = hmac.new(config.SECRET.encode(), (dn + date).encode(), hashlib.sha256).digest()
    dn_signed = dn + "|" + date + "|" + base64.b64encode(dn_hmac).decode().strip()
    msg = "Mit diesem Link kannst du dich einloggen und dein Passwort aendern:\n" \
          "https://%s/login?%s\n" % (config.DOMAIN, urlencode({'token': dn_signed}))
    notification.send_notification(mail,
                                   "[flipdot-noti] Passwort-Reset",
                                   msg)
    print(msg)
    return render_template("success.html", message="You should have gotten a mail.")


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/list')
def list():
    ldap = FlipdotUser()
    ldap.login(session['username'], session['password'])
    user = ldap.getuser(session['username'])
    user_list = ldap.get_all_users()
    return render_template('list.html', users=user_list, login_user=user)


@app.route('/user/impersonate', methods=["GET"])
def impersonate():
    user = request.args.get('user')
    if not user:
        return render_template("error.html", message="Not a valid user")
    dn, data = FlipdotUser().getuser(session['username'])
    if not data['meta']['is_admin']:
        return render_template("error.html", message=u"No. 😾")

    dn_imp, data_imp = FlipdotUser().getuser(user)

    session['username'] = user
    return redirect('/')


@app.route('/add', methods=['POST', 'GET'])
def add():
    form = LdapForm(request.form)
    if request.method == 'POST' and form.validate():
        try:
            fd = FlipdotUser()
            fd.login(session['username'], session['password'])
            fd.createUser(form.uid.data,
                          form.sammyNick.data,
                          form.mail.data,
                          form.password.data)
            return redirect(url_for('list'))
        except LDAPException as e:
            return render_template("error.html", message=str(e))

    return render_template('add.html', form=form)


@app.route('/user/<uid>', methods=['DELETE'])
def delete(uid):
    if uid is None:
        return render_template("error.html", message="must supply uid")
    try:
        fd = FlipdotUser()
        fd.login(session['username'], session['password'])
        #admin_data = fd.getuser(session['username'])
        #_ = fd.getuser(uid)
        fd.delete(uid)
    except LDAPException as e:
        return "Error: " + str(e)
    return "OK"


def get_anonymous():
    fd = FlipdotUser()
    fd.login_dn(config.LDAP_RO_USER, config.LDAP_RO_PASSWORD)
    return fd


@app.route('/system/who_is_in_config')
def who_is_in_config():
    fd = get_anonymous()
    users = fd.get_all_users()
    macs = []
    for user in users:
        if 'macAddress' not in user:
            continue
        sammyNick = user['sn'][0]
        sammyNick = sammyNick.replace('/', '\\/')
        for mac in user['macAddress']:
            mac = mac.replace('-', ':').strip()
            macs.append("s/%s/%s/i" % (mac, sammyNick))
    return Response('\n'.join(macs) + '\n', mimetype='text/plain')


@app.route('/system/who_is_in_config2')
def who_is_in_config2():
    fd = get_anonymous()
    users = fd.get_all_users()
    macs = {}
    for user in users:
        if 'macAddress' not in user:
            continue
        sammyNick = user['sn'][0]
        sammyNick = sammyNick.replace('/', '\\/')
        for mac in user['macAddress']:
            mac = mac.replace('-', ':').strip()
            macs[mac] = sammyNick
    return macs


@app.route('/system/ssh_keys')
def ssh_keys():
    fd = get_anonymous()
    users = fd.get_all_users()
    ssh_keys = []
    for user in users:
        if 'sshPublicKey' not in user:
            continue
        if user.get("isFlipdotMember", False):
            for key in user['sshPublicKey']:
                cleanuser = re.sub(r'[^a-zA-Z0-9]', '', user['cn'][0])
                # command = 'command="/home/door/door.py ' + cleanuser + '"'
                # ssh_keys.append(command + " " + key + " " + cleanuser)
                ssh_keys.append(key + " " + cleanuser)
    return Response('\n'.join(ssh_keys) + '\n', mimetype='text/plain')


@app.route('/system/rfid_keys')
def rfid_keys():
    server = ldap3.Server(config.LDAP_HOST)
    c = Connection(server)
    c.bind()
    c.search(search_base="ou=members,dc=flipdot,dc=org",
             search_filter="(&(objectClass=flipdotter)(isFlipdotMember=TRUE))", attributes=['rfid'])
    users = c.response
    rfid_keys = []
    for user in users:
        if user.get("isFlipdotMember", False):
            for tag in user['rfid']:
                rfid_keys.append(tag)
    return Response('\n'.join(rfid_keys) + '\n', mimetype='text/plain')


@app.errorhandler(500)
def internal_error(error):
    # if it's a FrontendError, show the message
    if isinstance(error, FrontendError):
        return render_template("error.html", message=error.message)
    else:
        return 'Internal server error. Checkout <a target="_blank" href="https://glitchtip.flipdot.org/flipdot/issues?project=3">Glitchtip</a> for more information'


if __name__ == '__main__':
    if not app.debug:
        import logging
        from logging import FileHandler

        file_handler = FileHandler(config.LOG_FILE)
        file_handler.setLevel(logging.WARNING)
        app.logger.addHandler(file_handler)

    app.run(port=config.PORT, debug=config.DEBUG)
