from flask import Flask, session, redirect, url_for, request, render_template
import config
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
    if request.method == "POST":
        if not form.validate():
            return render_template('index.html', form=form)

        dn, data = FlipdotUser().getuser(session['username'])
        new = copy.deepcopy(data)

        new['sshPublicKey'][0] = form.sshKey1.data.encode('ascii', 'ignore')
        new['sshPublicKey'][1] = form.sshKey2.data.encode('ascii', 'ignore')

        if form.password.data != '':
            oldPw = form.oldPassword.data.encode('ascii', 'ignore')
            newPw = form.password.data.encode('ascii', 'ignore')
            print("update pw")
            FlipdotUser().setPasswd(dn, oldPw, newPw)

        FlipdotUser().setuserdata(dn, data, new)

        return redirect(url_for('user'))

    dn, data = FlipdotUser().getuser(session['username'])
    form.uid.data = data['uid'][0]
    form.sshKey1.data = get(data.get('sshPublicKey', ['']), 0)
    form.sshKey2.data = get(data.get('sshPublicKey', ['']), 1)
    form.mail.data = data.get('mail', [''])[0]
    return render_template('index.html', form=form)


@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        uid = request.form.get('uid', '')
        pwd = request.form.get('password', '')
        valid, dn = FlipdotUser().login(uid, pwd)
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
    user_list = FlipdotUser().getusers('*')
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
