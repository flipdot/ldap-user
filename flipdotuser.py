import json
import ldap
import ldap.modlist as modlist
import ldap.filter
import os
import re

import config


'''
If you are generating the LDAP filter dynamically (or letting users specify the filter),
then you may want to use the escape_filter_chars() and filter_format() functions in the ldap.filter
 module to keep your filter strings safely escaped.
'''
class FlipdotUser:

    def connect(self, dn, pw):
        from .webapp import FrontendError
        try:
            #ldap.set_option(ldap.OPT_DEBUG_LEVEL, 4095)
            con = ldap.initialize(config.LDAP_HOST, trace_level=0)
            con.simple_bind_s(dn, pw)
        except ldap.SERVER_DOWN as e:
            err_msg = e.message['desc']
            raise FrontendError(err_msg)
        return con

    def login(self, username, password):
        dn = ldap.filter.escape_filter_chars(config.LDAP_USER_DN.format(username))
        try:
            con = self.connect(dn, ldap.filter.escape_filter_chars(password))
            con.unbind()
            return True, dn
        except ldap.INVALID_CREDENTIALS:
            print("invalid")
            return False, None
        except Exception as e:
            raise e

    def get_meta(self, data):
        meta_str = data.get('postOfficeBox', [None])[0]
        default_meta = {
            "drink_notification": "instant",  # instant, daily, weekly, never
            "last_drink_notification": 0,
            "is_admin": False,
            "is_member": False,
            "hue": 0,
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
            if not key in meta:
                meta[key] = value
        return meta

    def set_meta(self, data, meta):
        meta_str = json.dumps(meta).encode('utf8', 'ignore')
        if not 'postOfficeBox' in data:
            data['postOfficeBox'] = [None]
        data['postOfficeBox'][0] = meta_str

    def getusers(self, filter):
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)
        base_dn = "ou=members,dc=flipdot,dc=org"
        attrs = ['uid', 'sshPublicKey', 'mail', 'cn', 'sn', 'uidNumber', 'macAddress', 'objectclass', 'postOfficeBox', 'employeeNumber']
        users = con.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        con.unbind()

        for _dn, user in users:
            for key, val in user.items():
                user[key] = [x.decode() for x in val]
            user['meta'] = self.get_meta(user)
        return users

    def getuser(self, uid):
        r = re.match("cn=(.*),ou=.*", uid)
        search_filter = '(&(objectclass=person) (cn={:s}))'.format(ldap.filter.escape_filter_chars(r.group(1)))
        user = self.getusers(search_filter)
        return user[0] if user else None


    def get_all_users(self):
        search_filter = '(&(objectclass=person))'
        users = self.getusers(search_filter)
        reverse_users = sorted(users, key=lambda tup: int(tup[1].get('uidNumber', ['0'])[0]), reverse=True)
        return reverse_users


    def setuserdata(self, dn, new, session):
        all_classes = self.ensure_object_classes({})
        user = self.getuser(dn)
        old = user[1]

        add_object_classes = []
        for c in all_classes['objectclass']:
          if not c in user[1]['objectClass']:
            add_object_classes.append(c)

        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)

        if old['uid'][0] != new['uid'][0] or old['cn'][0] != new['cn'][0] \
                or old['uid'][0] != new['cn'][0] or old['cn'][0] != new['uid'][0]:
            old_dn = config.LDAP_USER_DN.format(old['cn'][0])
            new_dn = config.LDAP_USER_DN.format(new['uid'][0])
            new_rdn = new_dn.split(',')[0]
            new_ou = ",".join(new_dn.split(',')[1:])
            con.rename_s(old_dn, new_rdn, new_ou)
            dn = new_dn
            session['username'] = dn

        # ensure object classes
        con.modify_s(dn, modlist.modifyModlist({}, {'objectClass':add_object_classes}))

        self.set_meta(new, new['meta'])
        del (new['meta'])
        del (old['meta'])
        # safe new attribtes
        ldif = modlist.modifyModlist(old, new)
        new['meta'] = self.get_meta(new)

        con.modify_s(dn, ldif)

        con.unbind()


    def setPasswd(self, dn, old, new):
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)
        con.passwd_s(dn, old, new)
        con.unbind()


    def delete(self, dn):
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)
        con.delete_s(dn)

    def ensure_object_classes(self, attrs):
        attrs['objectclass'] = ['top', 'inetOrgPerson', 'ldapPublicKey', 'organizationalPerson',
                                'person', 'posixAccount', 'ieee802Device']
        return attrs

    def createUser(self, uid, sammyNick, mail, pwd):
        new_uid = self.get_new_uid()
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)

        dn = config.LDAP_USER_DN.format(ldap.filter.escape_filter_chars(sammyNick))

        attrs = {}
        self.ensure_object_classes(attrs)
        attrs['uid'] = ldap.filter.escape_filter_chars(uid)
        attrs['sn'] = ldap.filter.escape_filter_chars(sammyNick)
        attrs['mail'] = ldap.filter.escape_filter_chars(mail)
        attrs['uidNumber'] = str(new_uid)
        attrs['gidNumber'] = config.LDAP_MEMBER_GID
        attrs['homeDirectory'] = ldap.filter.escape_filter_chars('/home/{:s}'.format(uid))

        ldif = modlist.addModlist(attrs)

        con.add_s(dn, ldif)
        con.passwd_s(dn, None, pwd)
        con.unbind_s()

    def get_new_uid(self):
        users = self.get_all_users()

        last = users[0]
        return int(last[1]['uidNumber'][0])+1
