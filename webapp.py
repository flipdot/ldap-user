#!/usr/bin/env python2
from flask import Flask, session, redirect, url_for, request, render_template
import copy
import config
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
    return render_template('index.html', form=form)


def remove_deleted_entry(form_list):
    tmp = []
    for x in range(0, len(form_list.data)):
        key = form_list.pop_entry()
        if not key.data['delete']:
            tmp.append(key)
    for x in tmp[::-1]:
        form_list.append_entry(x.data)


@app.route('/login', methods=['POST'])
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

    return redirect(url_for('index'))


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


if __name__ == '__main__':
    app.secret_key = config.SECRET
    app.run()


class Error(Exception):
    pass

class FrontendError(Error):

    def __init__(self, message):
        self.message = message

