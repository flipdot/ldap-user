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

        #ldap.set_option(ldap.OPT_DEBUG_LEVEL, 4095)
        ca_cert = os.getcwd()+"/cacert.pem"
        if not os.path.isfile(ca_cert):
            print "cert not found"
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ca_cert)
        con = ldap.initialize(config.LDAP_HOST, trace_level=0)
        con.simple_bind_s(dn, pw)
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

    def getusers(self, uidFilter):
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)
        base_dn = "ou=members,dc=flipdot,dc=org"
        filter = '(&(objectclass=person) (cn={:s}))'.format(ldap.filter.escape_filter_chars(uidFilter))
        attrs = ['uid', 'sshPublicKey', 'mail', 'cn', 'uidNumber']
        user = con.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        con.unbind()
        return user


    def getuser(self, uid):
        r = re.match("cn=(.*),ou=.*", uid)
        user = self.getusers(r.group(1))
        return user[0]

    def setuserdata(self, dn, old, new):
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)
        ldif = modlist.modifyModlist(old, new)
        con.modify_s(dn, ldif)
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
        #TODO uidNumber autoincrement?
        attrs['uidNumber'] = str(new_uid)
        attrs['gidNumber'] = config.LDAP_MEMBER_GID
        attrs['homeDirectory'] = ldap.filter.escape_filter_chars('/home/{:s}'.format(uid))

        ldif = modlist.addModlist(attrs)

        con.add_s(dn, ldif)
        con.passwd_s(dn, pwd)
        con.unbind_s()

    def get_new_uid(self):
        con = self.connect(config.LDAP_ADMIN_DN, config.LDAP_ADMIN_PW)
        base_dn = "ou=members,dc=flipdot,dc=org"
        filter = '(&(objectclass=*))'
        attrs = ['uidNumber']
        user = con.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)

        last = sorted(user, key=lambda tup: int(tup[1].get('uidNumber', ['0'])[0]), reverse=True)[0]
        con.unbind()
        return int(last[1]['uidNumber'][0])+1
