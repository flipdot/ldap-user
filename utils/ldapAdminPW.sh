bash -c "cd .. && python - <<EOF
import config
print(config.LDAP_ADMIN_PW)
EOF"
