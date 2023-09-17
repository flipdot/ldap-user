from wtforms import Form, StringField, PasswordField, FieldList, SubmitField, \
    validators, FormField, ValidationError, SelectField, IntegerField, EmailField

from sshpubkeys import SSHKey, InvalidKeyException
from wtforms.validators import InputRequired


def ssh_key_check(form, field):
    ssh = SSHKey(field.data, strict_mode=True)
    try:
        ssh.parse()
    except (InvalidKeyException, NotImplementedError):
        raise ValidationError('Invalid SSHPublicKey')


class ListSSHForm(Form):
    entry = StringField("SSHPublicKey", [InputRequired(), ssh_key_check])
    delete = SubmitField('Delete')


class ListMacForm(Form):
    entry = StringField("MAC-Address")
    delete = SubmitField('Delete')


class LdapForm(Form):
    uid = StringField('Username', validators=[
        validators.Length(min=2, max=25, message="Username length is baad. min: 2, max: 25"),
        validators.DataRequired(message="Username is required")])
    sammyNick = StringField('BananaNick', validators=[
        validators.Length(min=2, max=25, message="BananaNick is baad. min: 2, max: 25"),
        validators.DataRequired(message="BanaNick is required!")])
    drink_notification = SelectField('Drink Notification',
                                     default='instant',
                                     choices=[
                                         ("instant", "instant"),
                                         ("daily", "daily"),
                                         ("instant and daily", "instant and daily"),
                                         ("weekly", "weekly"),
                                         ("instant and weekly", "instant and weekly"),
                                         ("never", "never"),
                                     ])
    oldPassword = PasswordField('Old password')
    password = PasswordField('New password', [
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat new password')

    mail = EmailField("Email", validators=[validators.Email(message="Email is invalid!")])

    sshKeys = FieldList(FormField(ListSSHForm))
    macs = FieldList(FormField(ListMacForm))


class PasswdForm(Form):
    password = PasswordField('New password', [
        validators.Length(min=6, message="Your password must be 6 characters minimum."),
        validators.EqualTo('confirm', message='Passwords must match.')
    ])
    confirm = PasswordField('Repeat new password')
