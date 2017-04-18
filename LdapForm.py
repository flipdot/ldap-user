from wtforms import Form, StringField, PasswordField, validators
from wtforms.fields.html5 import EmailField


class LdapForm(Form):
    uid = StringField('Username', validators=[
        validators.Length(min=4, max=25, message="Username length is baad. min: 4, max: 25"),
        validators.DataRequired(message="Username is required")])
    sammyNick = StringField('SammyNick', validators=[
        validators.Length(min=4, max=25, message="BananaNick is baad. min: 4, max: 25"),
        validators.DataRequired(message="BanaNick is required!")])

    oldPassword = PasswordField('Old Password')
    password = PasswordField('New Password', [
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')

    mail = EmailField("Email", validators=[validators.Email(message="Email is invalid!")])

    sshKey1 = StringField('SShPublicKey')
    sshKey2 = StringField('Alt. SSHPublicKey')

