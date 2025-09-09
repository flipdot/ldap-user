import json
import ldap3
import os
import re

from ldap3.core.exceptions import LDAPException, LDAPExceptionError, LDAPBindError, LDAPInvalidCredentialsResult
from ldap3.utils.hashed import hashed
from ldap3 import Connection, Reader, Writer, ObjectDef


import config
from flipdot_error import FrontendError

'''
If you are generating the LDAP filter dynamically (or letting users specify the filter),
then you may want to use the escape_filter_chars() and filter_format() functions in the ldap.filter
 module to keep your filter strings safely escaped.
'''


class FlipdotUser:

    def __init__(self):
        self.con = None

    def connect(self, dn, pw):
        try:
            server = ldap3.Server(config.LDAP_HOST)
            con = ldap3.Connection(server, user=dn, password=pw, auto_bind='DEFAULT', raise_exceptions=True)
            con.bind()

        except LDAPExceptionError as e:
            err_msg = str(e)
            raise FrontendError(err_msg)
        self.con = con
        return con

    def login_dn(self, username, password):
        dn = username
        try:
            con = self.connect(dn, password)

            return True
        except LDAPInvalidCredentialsResult:
            print("invalid")
            return False
        except Exception as e:
            raise e

    def login(self, username, password):
        return self.login_dn(config.LDAP_USER_DN.format(username), password)

    def get_meta(self, data):
        meta_str = data.get('postOfficeBox', [None])
        default_meta = {
            "drink_notification": "instant",  # instant, daily, weekly, never
            "last_drink_notification": 0,
            "is_admin": False,
            "is_member": False,
        }
        meta = default_meta
        if meta_str:
            try:
                meta_o = json.loads(meta_str)
                if type(meta_o) == dict:
                    meta = meta_o
            except:
                pass
        for key, value in default_meta.items():
            if key not in meta:
                meta[key] = value
        return meta

    def set_meta(self, data, meta):
        meta_str = json.dumps(meta).encode('utf8', 'ignore')
        if not 'postOfficeBox' in data:
            data['postOfficeBox'] = [None]
        data['postOfficeBox'][0] = meta_str

    def getusers(self, filter):

        base_dn = "ou=members,dc=flipdot,dc=org"
        attrs = ['uid', 'sshPublicKey', 'mail', 'cn', 'sn', 'uidNumber', 'macAddress', 'objectclass', 'postOfficeBox',
                 'employeeNumber', 'rfid', 'drinksNotification', 'isFlipdotMember']
        users = self.con.search(search_base=base_dn,
                                search_filter=filter,
                                search_scope=ldap3.SUBTREE,
                                attributes=attrs,
                                )
        users = self.con.response

        admins = self.con.search(search_base="ou=flipmins,dc=flipdot,dc=org",
                                search_filter='(objectClass=groupOfNames)',
                                search_scope=ldap3.SUBTREE,
                                attributes=['member'])

        admins = self.con.response[0].get("attributes").get("member") if admins else []
        # users = self.con.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)

        for user in users:
            for key, val in user['attributes'].items():
                if type(val) is list:
                    val = [x.decode('utf-8') if type(x) is bytes else x for x in val]
                user[key] = val
            user['meta'] = self.get_meta(user)
            user['meta']['is_admin'] = user['dn'] in admins
        return users

    def getuser(self, uid):
        r = re.match("cn=(.*),ou=.*", uid)
        if r:
            uid = r.group(1)
        search_filter = f'(&(objectclass=person) (cn={uid}))'
        user = self.getusers(search_filter)
        return user[0] if user else None

    def get_all_users(self):
        search_filter = '(&(objectclass=person))'
        users = self.getusers(search_filter)
        reverse_users = sorted(users, key=lambda tup: int(tup.get('uidNumber', 0)), reverse=True)
        return reverse_users

    def setuserdata(self, dn, new):
        o = ObjectDef(['inetOrgPerson', 'flipdotter'], self.con)

        r = Reader(self.con, o, dn)
        r.search()

        w = Writer.from_cursor(r)
        e = w[0]

        change_cn = e['uid'] != new['uid']
        for k, v in new.items():
            if k in e and not (isinstance(v, list) and not v):
                e[k] = v
            else:
                print(f"unknown key {k}")

        ret = e.entry_commit_changes()
        if ret and change_cn:
            s = ldap3.Server('ldapi:///var/run/slapd/ldapi')
            c = Connection(s, authentication=ldap3.SASL, sasl_mechanism=ldap3.EXTERNAL, sasl_credentials='')
            c.bind()
            ret = ret and c.modify_dn(dn, f'cn={new["uid"]}')
            c.unbind()

        return ret

    def setPasswd(self, dn, old, new):
        self.login_dn(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PASSWORD)
        self.con.extend.standard.modify_password(dn, old, new)

    def delete(self, dn):
        self.con.delete(dn)

    def ensure_object_classes(self):
        return ['top', 'inetOrgPerson', 'ldapPublicKey', 'organizationalPerson',
                'person', 'posixAccount', 'ieee802Device', 'flipdotter']


    def createUser(self, uid, sammyNick, mail, pwd):
        self.create_user(uid, sammyNick, mail, pwd)

    def create_user(self, username, public_nick, mail, pwd):
        new_uid = self.get_new_uid()
        dn = config.LDAP_USER_DN.format(username)

        return self.con.add(dn,
                            self.ensure_object_classes(),
                            {
                                "uid": username,
                                "sn": public_nick,
                                "mail": mail,
                                "uidNumber": str(new_uid),
                                "gidNumber": config.LDAP_MEMBER_GID,
                                "homeDirectory": f"/home/{username}",
                                "userPassword": hashed(ldap3.HASHED_SHA, pwd),
                                "isFlipdotMember": False,
                            })

    def get_new_uid(self):
        users = self.get_all_users()

        last = users[0]
        return int(last['uidNumber']) + 1
