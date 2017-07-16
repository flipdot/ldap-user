bash -c "cd .. && python - <<EOF
import config
import sys

sys.stdout.write(config.LDAP_ADMIN_PW)
EOF"
