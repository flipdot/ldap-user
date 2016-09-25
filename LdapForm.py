from wtforms import Form, StringField, PasswordField, validators
from wtforms.fields.html5 import EmailField


class LdapForm(Form):
    uid = StringField('Username', validators=[validators.Length(min=4, max=25), validators.DataRequired()])
    sammyNick = StringField('SammyNick', validators=[validators.Length(min=4, max=25), validators.DataRequired()])

    oldPassword = PasswordField('Old Password')
    password = PasswordField('New Password', [
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')

    mail = EmailField("Email", validators=[validators.Email()])

    sshKey1 = StringField('SShPublicKey')
    sshKey2 = StringField('Alt. SSHPublicKey')

