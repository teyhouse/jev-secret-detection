"""Config batch: credentials that look exactly like ordinary configuration.

Every value here is low entropy, has no vendor prefix, and sits in a real config file format. Nothing in the
string itself says "credential", so the label can only be decided by asking whether the value is the right kind
of value for the field it is written into: `password Mailer-Relay-7719` in an msmtp account block is a working
mail password, while `passwordeval "pass show smtp/brightmoor"` in the same slot is a command that fetches one.

This is the class that prefix and entropy rules cannot reach. Pattern rules key off issued formats (ghp_, sk_live_,
xoxb-) and entropy filters need a value that looks random, so an ops-chosen password like `Depot-Forklift-5518`
scores like a product name. SecretBench, built by running TruffleHog and Gitleaks over 818 repositories, labeled
only 150 true passwords and 27 true usernames out of 15,084 true secrets, which is the shape of what those tools
surface rather than the shape of what leaks.

The 20 cases are 11 secrets and 9 non-secrets, mostly in pairs that share a file and a field and differ only in
the value. The non-secrets are the config-shaped false positives: password hashes and SCRAM verifiers in a
credential file, pointers to a file or a password manager, Java's documented `changeit` truststore default, a
gateway section where every field name says api_key but no key is set, and test seed users with joke passwords.

All passwords were invented for this file and have never been valid. The hashes are genuine apr1, bcrypt, SCRAM
and pgbouncer-md5 digests of invented passwords, so they have the right structure without protecting anything.
"""

from fixtures import Case

CASES = {
    # secret: yes - Working SMTP relay password in an msmtp account block. Nothing marks the value as special: it
    # is a word-and-digits string in a plain `password` field. Pair: cfg_002.
    "cfg_001": Case(
        file_path="roles/mail/files/msmtprc",
        content=(
            "defaults\n"
            "auth on\n"
            "tls on\n"
            "tls_trust_file /etc/ssl/certs/ca-certificates.crt\n"
            "\n"
            "account brightmoor\n"
            "host smtp.brightmoor.internal\n"
            "port 587\n"
            "from alerts@brightmoor.internal\n"
            "user alerts@brightmoor.internal\n"
            "password Mailer-Relay-7719\n"
            "\n"
            "account default : brightmoor"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: no - Same account block, but the password comes from a password manager at runtime. The credential
    # slot holds a command, not a credential. Pair: cfg_001.
    "cfg_002": Case(
        file_path="roles/mail/files/msmtprc",
        content=(
            "defaults\n"
            "auth on\n"
            "tls on\n"
            "tls_trust_file /etc/ssl/certs/ca-certificates.crt\n"
            "\n"
            "account brightmoor\n"
            "host smtp.brightmoor.internal\n"
            "port 587\n"
            "from alerts@brightmoor.internal\n"
            "user alerts@brightmoor.internal\n"
            'passwordeval "pass show smtp/brightmoor/alerts"\n'
            "\n"
            "account default : brightmoor"
        ),
        expected_secret=False,
        category="reference",
    ),
    # secret: yes - LDAP service account bind password. `bindpw` is the password for the `binddn` above it, and the
    # value is a real chosen one, so anyone with the file can bind and read the directory. Pair: cfg_004.
    "cfg_003": Case(
        file_path="etc/nslcd.conf",
        content=(
            "uri ldaps://ldap.brightmoor.internal\n"
            "base dc=brightmoor,dc=internal\n"
            "binddn cn=nslcd,ou=service,dc=brightmoor,dc=internal\n"
            "bindpw Svc-Ldap-Bind-7742\n"
            "ssl on\n"
            "tls_cacertfile /etc/ssl/certs/brightmoor-ca.pem"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: no - Same file shipped with the bind password left as an instruction to fill in. Pair: cfg_003.
    "cfg_004": Case(
        file_path="etc/nslcd.conf",
        content=(
            "uri ldaps://ldap.brightmoor.internal\n"
            "base dc=brightmoor,dc=internal\n"
            "binddn cn=nslcd,ou=service,dc=brightmoor,dc=internal\n"
            "bindpw CHANGE_ME_BEFORE_DEPLOY\n"
            "ssl on\n"
            "tls_cacertfile /etc/ssl/certs/brightmoor-ca.pem"
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - pgbouncer userlist with the passwords stored in plain text, which the format allows. Both
    # values are usable against the database. Pair: cfg_006.
    "cfg_005": Case(
        file_path="etc/pgbouncer/userlist.txt",
        content='"billing_app" "Ledger-Wharf-6021"\n"reporting_ro" "Report-Gantry-4402"',
        expected_secret=True,
        category="password",
    ),
    # secret: no - Same userlist for the same two users, stored as a SCRAM verifier and a pgbouncer md5 hash.
    # Neither can be replayed as a password. Pair: cfg_005.
    "cfg_006": Case(
        file_path="etc/pgbouncer/userlist.txt",
        content=(
            '"billing_app" "SCRAM-SHA-256$4096:Uv0OT++lyT5B5TkQdyY0fQ==$'
            'aH3qdVQcCXJs3LZYL8G2y6JM/ykWJxVuOl5ktnGos5g=:wRt6Kyw62Jq03UWmkf3Recpk+weO63YVFKmglTSmHu4="\n'
            '"reporting_ro" "md55fe37137d8eec3ccf6b205be904234e4"'
        ),
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: yes - Spring datasource password for the production database, next to the host it opens. The value
    # reads like a release name, which is the whole problem. Pair: cfg_008.
    "cfg_007": Case(
        file_path="src/main/resources/application-prod.properties",
        content=(
            "spring.datasource.url=jdbc:postgresql://db-prod-02.brightmoor.internal:5432/billing\n"
            "spring.datasource.username=billing_app\n"
            "spring.datasource.password=Quarter-Close-3318\n"
            "spring.jpa.hibernate.ddl-auto=validate\n"
            "management.endpoints.web.exposure.include=health,info"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: no - Same file, and a field that also ends in `password`, but `changeit` is the documented Java
    # default and the store it opens holds public CA certificates. Pair: cfg_007.
    "cfg_008": Case(
        file_path="src/main/resources/application-prod.properties",
        content=(
            "server.ssl.trust-store=classpath:truststore.jks\n"
            "server.ssl.trust-store-type=JKS\n"
            "server.ssl.trust-store-password=changeit\n"
            "spring.datasource.url=jdbc:postgresql://db-prod-02.brightmoor.internal:5432/billing\n"
            "spring.jpa.hibernate.ddl-auto=validate"
        ),
        expected_secret=False,
        category="public_value",
    ),
    # secret: yes - strongSwan pre-shared key for the site-to-site tunnel. Reads like a passphrase someone picked,
    # because it is. Pair: cfg_010.
    "cfg_009": Case(
        file_path="etc/ipsec.secrets",
        content=(
            "# /etc/ipsec.secrets - strongSwan IPsec secrets file\n"
            '203.0.113.9 198.51.100.4 : PSK "harbor-lantern-ridge-42"'
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: no - The tunnel definition that goes with it. `authby=secret` names the authentication method; the
    # key itself lives in ipsec.secrets. Pair: cfg_009.
    "cfg_010": Case(
        file_path="etc/ipsec.conf",
        content=(
            "conn brightmoor-dc1\n"
            "    left=203.0.113.9\n"
            "    leftsubnet=10.4.0.0/16\n"
            "    right=198.51.100.4\n"
            "    rightsubnet=10.9.0.0/16\n"
            "    authby=secret\n"
            "    ike=aes256-sha256-modp2048\n"
            "    esp=aes256gcm16\n"
            "    auto=start"
        ),
        expected_secret=False,
        category="no_credential",
    ),
    # secret: yes - CIFS mount password written into the fstab options, where it sits between two mount flags and
    # looks like one. Pair: cfg_012.
    "cfg_011": Case(
        file_path="etc/fstab",
        content=(
            "UUID=6f4c1d9e-3a52-4b8f-9c07-2e5d18ab7c30  /  ext4  defaults  0 1\n"
            "//files-01.brightmoor.internal/backups  /mnt/backups  cifs  "
            "username=svc_backup,password=Fileshare-Winter-2026,vers=3.1.1,uid=1001,_netdev  0 0"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: no - Same mount, with the credentials moved into a root-only file that fstab points at. Pair: cfg_011.
    "cfg_012": Case(
        file_path="etc/fstab",
        content=(
            "UUID=6f4c1d9e-3a52-4b8f-9c07-2e5d18ab7c30  /  ext4  defaults  0 1\n"
            "//files-01.brightmoor.internal/backups  /mnt/backups  cifs  "
            "credentials=/etc/cifs/backup.cred,vers=3.1.1,uid=1001,_netdev  0 0"
        ),
        expected_secret=False,
        category="reference",
    ),
    # secret: yes - SNMP read community string, which is the credential for querying the device. No field name says
    # password or key, and the value is not the `public` default, so it was chosen for this network.
    "cfg_013": Case(
        file_path="roles/monitoring/files/snmpd.conf",
        content=(
            "agentAddress udp:161\n"
            "rocommunity Brightmoor-NetRO-2231 10.4.0.0/16\n"
            "syslocation DC1 Rack 14\n"
            "syscontact netops@brightmoor.internal\n"
            "dontLogTCPWrappersConnects yes"
        ),
        expected_secret=True,
        category="generic_secret",
    ),
    # secret: yes - Kafka SASL password, buried inside the one-line JAAS config string next to a Java class name.
    "cfg_014": Case(
        file_path="deploy/kafka/client.properties",
        content=(
            "bootstrap.servers=kafka-01.brightmoor.internal:9093,kafka-02.brightmoor.internal:9093\n"
            "security.protocol=SASL_SSL\n"
            "sasl.mechanism=SCRAM-SHA-512\n"
            "sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required "
            'username="svc_ingest" password="ingest-broker-9047";\n'
            "ssl.truststore.location=/etc/kafka/truststore.jks"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: yes - Grafana admin password in the security section. The value is a plausible rotation label, and the
    # account it opens owns every dashboard and data source.
    "cfg_015": Case(
        file_path="deploy/grafana/grafana.ini",
        content=(
            "[server]\n"
            "root_url = https://grafana.brightmoor.internal\n"
            "\n"
            "[security]\n"
            "admin_user = ops\n"
            "admin_password = Dashboard-Rotate-4417\n"
            "cookie_secure = true\n"
            "disable_gravatar = true"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: yes - Wi-Fi pre-shared key for the depot network. `psk` never appears in a token allowlist and the
    # value looks like a site name, but it is what joins the network.
    "cfg_016": Case(
        file_path="provisioning/wpa_supplicant.conf",
        content=(
            "ctrl_interface=/run/wpa_supplicant\n"
            "update_config=1\n"
            "country=DE\n"
            "\n"
            "network={\n"
            '\tssid="Brightmoor-Depot"\n'
            '\tpsk="Depot-Forklift-5518"\n'
            "\tkey_mgmt=WPA-PSK\n"
            "\tpriority=10\n"
            "}"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: yes - Ansible sudo password committed in plain group_vars, beside ordinary inventory variables.
    "cfg_017": Case(
        file_path="group_vars/prod/vars.yml",
        content=(
            "ansible_user: deploy\n"
            "ansible_become: true\n"
            "ansible_become_pass: Harbor-Deploy-2288\n"
            "postgres_host: db-prod-02.brightmoor.internal\n"
            "postgres_port: 5432\n"
            "app_replicas: 4"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: no - Basic auth file for the metrics endpoint. It is a credential store, but it holds an apr1 and a
    # bcrypt hash, so there is no password to read out.
    "cfg_018": Case(
        file_path="deploy/nginx/.htpasswd",
        content=(
            "ops:$apr1$bHp78M.Q$B7LLg6kJ9IBfYZ0TXxjPX/\nci:$2b$10$.gVtSYY3Jcw2j.HioLgu7.72XaSoBrO35hsr9GQ7AUQf7o1QwCtzq"
        ),
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: no - Gateway section where every field name says api_key, but the values are a header name, a length
    # rule, a TTL, and the prefix the gateway expects keys to start with. No key is set here.
    "cfg_019": Case(
        file_path="config/gateway.toml",
        content=(
            "[auth]\n"
            'api_key_header = "X-Brightmoor-Api-Key"\n'
            'api_key_prefix = "bm_live_"\n'
            "api_key_min_length = 32\n"
            'api_key_cache_ttl = "5m"\n'
            'hmac_header = "X-Brightmoor-Signature"\n'
            'hmac_algorithm = "sha256"'
        ),
        expected_secret=False,
        category="no_credential",
    ),
    # secret: no - Seed users for the test suite. The names and all three passwords are stock examples, so nothing
    # here opens a real account.
    "cfg_020": Case(
        file_path="tests/fixtures/users.yml",
        content=(
            "- username: alice\n"
            "  password: hunter2\n"
            "  role: admin\n"
            "- username: bob\n"
            "  password: correct horse battery staple\n"
            "  role: viewer\n"
            "- username: carol\n"
            "  password: letmein\n"
            "  role: viewer"
        ),
        expected_secret=False,
        category="placeholder",
    ),
}
