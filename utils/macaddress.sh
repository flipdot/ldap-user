SED_FILE=/tmp/ldap_macs.sed

PASSWORD=$(cat ldapAdminPW.sh)

rm -f $SED_FILE
macs=()
IFS_BACKUP=$IFS
IFS=$'\n'
for x in `ldapsearch -h rail.fd -D cn=admin,dc=flipdot,dc=org -b ou=members,dc=flipdot,dc=org -w $PASSWORD sn macAddress | grep -v "^#"`; do
        IFS=$IFS_BACKUP
        if [[ $x =~ ^sn:\ .*$ ]] ; then
                MACUSER=`echo -n "$x" | sed -rn 's/^sn: (.*)$/\1/p'`
        fi
        if [[ $x =~ ^sn::\ .*$ ]] ; then
                MACUSER=`echo -n "$x" | sed -rn 's/^sn:: (.*)$/\1/p' | base64 -d`
        fi
        if [[ $x =~ ^macAddress:.*$ ]] ; then
                MAC=`echo -n "$x" | sed -rn 's/^macAddress: ([0-9A-Fa-f:]*)$/\1/p'`
                macs+=($MAC)
        fi
        if [[ $x =~ ^dn:\ cn=.*$ || $x =~ ^search.*$ ]]; then
                echo "newline"
                for m in ${macs[@]}; do
                        echo "s/$m/$MACUSER/" >> $SED_FILE
                done
                macs=()
                unset MACUSER
        fi
done
