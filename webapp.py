#!/usr/bin/env python2
from flask import Flask, session, redirect, url_for, request, render_template
import copy
from flipdotuser import *
from LdapForm import *


app = Flask(__name__)


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

        #new['sshPublicKey'][0] = form.sshKey1.data.encode('ascii', 'ignore')
        new['cn'][0] = form.sammyNick.data.encode('ascii', 'ignore')
        new['uid'][0] = form.uid.data.encode('ascii', 'ignore')
        new.setdefault('mail', [''])[0] = (form.mail.data.encode('ascii', 'ignore'))

        new['sshPublicKey'] = [x.entry.data.encode('ascii', 'ignore') for x in form.sshKeys if len(x.entry.data) > 0]
        #for sshKey in form.sshKeys:

        #new.setdefault('sshPublicKey', ['', ''])[0] = (form.sshKey1.data.encode('ascii', 'ignore'))
        #new['sshPublicKey'][1] = (form.sshKey2.data.encode('ascii', 'ignore'))

        # remove empty fields
        #new['sshPublicKey'] = [x for x in new['sshPublicKey'] if len(x) > 0]

        if form.password.data != '':
            old_pw = form.oldPassword.data.encode('ascii', 'ignore')
            new_pw = form.password.data.encode('ascii', 'ignore')
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

    elif request.method == "POST":
        #form.sshKeys.data = filter(lambda x: not x['delete'], form.sshKeys.data)

        list = []
        for x in range(0, len(form.sshKeys.data)):
            key = form.sshKeys.pop_entry()
            if not key.data['delete']:
                list.append(key)

        for x in list[::-1]:
            form.sshKeys.append_entry(x.data)

        return render_template('index.html', form=form)

    form.uid.data = data['uid'][0]
    form.sammyNick.data = data['cn'][0]
    for key in data.get('sshPublicKey', []):
        e = ListSSHForm()
        e.entry = key
        e.delete = False
        form.sshKeys.append_entry(e)

    for key in data.get('macAddress', []):
        e = ListMacForm()
        e.entry = key
        e.delete = False
        form.macs.append_entry(e)

    form.mail.data = data.get('mail', [''])[0]
    form.password.data = ""
    form.oldPassword.data = ""
    form.confirm.data = ""
    return render_template('index.html', form=form)


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
        FlipdotUser().createUser(form.uid.data.encode('ascii', 'ignore'),
                                 form.sammyNick.data.encode('ascii', 'ignore'),
                                 form.mail.data.encode('ascii', 'ignore'),
                                 form.password.data.encode('ascii', 'ignore'))
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
