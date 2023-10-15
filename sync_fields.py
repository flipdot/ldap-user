import json

from ldap3 import Connection, Reader, Writer, ObjectDef

c = Connection('ldap.flipdot.space', 'cn=admin,dc=flipdot,dc=org', 'atmega328', auto_bind=True)
# o = ObjectDef('inetOrgPerson', c)
#
# r = Reader(c, o, 'ou=members,dc=flipdot,dc=org', query="!(objectclass=flipdotter)")
# r.search()
#
# w = Writer.from_cursor(r)
# for e in w:
#     j = json.loads(str(e.postOfficeBox))
#     #print(f"{e.uid} -> {j}")
#
#     if "flipdotter" not in e.objectclass:
#         print("add")
#         e.objectclass += "flipdotter"
#         e.entry_commit_changes()

o =  ObjectDef(['inetOrgPerson', 'flipdotter', 'person'], c)

r = Reader(c, o, 'ou=members,dc=flipdot,dc=org')
r.search()

w = Writer.from_cursor(r)
for e in w:
    j = json.loads(str(e.postOfficeBox))
    print(f"{e.uid} -> {j}")
    e.drinksNotification = j.get('drink_notification', "instant")
    e.lastDrinkNotification = j.get('last_drink_notification', 0)
    e.lastEmailed = j.get('last_emailed')
    e.isFlipdotMember = j.get('is_member', False)
    for x in e.employeeNumber:
        e.rfid += x
    for x in e.carLicense:
        e.drinksBarcode += x
    e.entry_commit_changes()
#e = w[0]


#x = e.entry_commit_changes()

#print(x)