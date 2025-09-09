SECRET = 'geheim'
LDAP_HOST = 'ldaps://ldap.flipdot.org:636/'
LDAP_USER_DN = "cn={:s},ou=members,dc=flipdot,dc=org"
LDAP_ADMIN_DN = "cn=admin,dc=flipdot,dc=org"
LDAP_ADMIN_PASSWORD = "password"
MAIL_FROM = 'bot@flipdot.org'
MAIL_HOST = 'mail.flipdot.org'
MAIL_PASSWORD = None
MAIL_PORT = 587
SENTRY_DSN = 'https://deadbeef@sentry.flipdot.org/1'

LDAP_MEMBER_GID = "10000"

LOG_FILE = "ldap-webapp.log"
PORT=5000

DOMAIN = "ldap.flipdot.space"

DEBUG=True
STAGING=True
