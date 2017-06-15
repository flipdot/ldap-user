import ldap
import ldap.modlist as modlist
import ldap.filter
import os
import re

import config
from webapp import FrontendError

'''
If you are generating the LDAP filter dynamically (or letting users specify the filter),
then you may want to use the escape_filter_chars() and filter_format() functions in the ldap.filter
 module to keep your filter strings safely escaped.
'''
class FlipdotUser:

    def connect(self, dn, pw):
        try:
            ldap.set_option(ldap.OPT_DEBUG_LEVEL, 4095)
            ca_cert = os.getcwd()+"/cacert.pem"
            if not os.path.isfile(ca_cert):
                print "cert not found"
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ca_cert)
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
            print "invalid"
            return False, None
        except Exception as e:
            raise e

    def getusers(self, filter):
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)
        base_dn = "ou=members,dc=flipdot,dc=org"
        attrs = ['uid', 'sshPublicKey', 'mail', 'cn', 'uidNumber', 'macAddress']
        user = con.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        con.unbind()
        return user

    def getuser(self, uid):
        r = re.match("cn=(.*),ou=.*", uid)
        search_filter = '(&(objectclass=person) (cn={:s}))'.format(ldap.filter.escape_filter_chars(r.group(1)))
        user = self.getusers(search_filter)
        return user[0]

    def get_all_users(self):
        search_filter = '(&(objectclass=person))'
        users = self.getusers(search_filter)
        reverse_users = sorted(users, key=lambda tup: int(tup[1].get('uidNumber', ['0'])[0]), reverse=True)
        return reverse_users

    def setuserdata(self, dn, old, new):
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)
        ldif = modlist.modifyModlist(old, new)
        res_type, res_data = con.modify_s(dn, ldif)
        con.unbind()

    def setPasswd(self, dn, old, new):
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)
        con.passwd_s(dn, old, new)
        con.unbind()

    def createUser(self, uid, sammyNick, mail, pwd):
        new_uid = self.get_new_uid()
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)

        dn = config.LDAP_USER_DN.format(ldap.filter.escape_filter_chars(sammyNick))

        attrs = {}
        attrs['objectclass'] = ['top', 'inetOrgPerson', 'ldapPublicKey', 'organizationalPerson',
                                'person', 'posixAccount']
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
