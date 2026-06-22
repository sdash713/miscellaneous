#!/bin/bash
set -e

# Update /etc/hosts
if ! grep -q "linux-client.lab.local" /etc/hosts; then
cat << 'EOF' >> /etc/hosts
192.168.56.10 ad-server.lab.local ad-server
192.168.56.11 linux-server.lab.local linux-server
192.168.56.12 linux-client.lab.local linux-client
EOF
fi
sed -i 's/127.0.2.1 linux-client linux-client/127.0.2.1 linux-client.lab.local linux-client/g' /etc/hosts

# Create local user matching the AD principal name
if ! id -u testuser >/dev/null 2>&1; then
  useradd -m -s /bin/bash testuser
  echo "testuser:Password123!" | chpasswd
fi

# Install Kerberos clients non-interactively
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y krb5-user libpam-krb5 openssh-client

# Copy Kerberos config
cp /vagrant/krb5.conf /etc/krb5.conf

# Configure GSSAPI in SSH system-wide client config
cat << 'EOF' >> /etc/ssh/ssh_config.d/gssapi.conf
Host linux-server.lab.local
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials yes
EOF

echo "Linux Client provisioned successfully."
