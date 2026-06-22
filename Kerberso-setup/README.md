# Kerberos GSSAPI Lab

This Vagrant project sets up a three-node Active Directory and Linux Kerberos test lab. It automates:
1. Setting up a Windows Server 2019 Domain Controller & Kerberos KDC (`ad-server.lab.local`).
2. Creating a service mapping for Linux SSH, and generating a keytab file.
3. Setting up an Ubuntu Linux server (`linux-server.lab.local`) configured for Kerberos GSSAPI SSH logons.
4. Setting up an Ubuntu Linux client (`linux-client.lab.local`) to request tickets via `kinit` and authenticate to the server without password entry.

## Architecture

| FQDN | IP Address | OS | Role |
|------|------------|----|------|
| `ad-server.lab.local` | `192.168.56.10` | Windows Server 2019 | Domain Controller & KDC |
| `linux-server.lab.local` | `192.168.56.11` | Ubuntu 22.04 | SSH Server / GSSAPI Service |
| `linux-client.lab.local` | `192.168.56.12` | Ubuntu 22.04 | SSH Client |

- Realm: `LAB.LOCAL`
- Service Principal: `host/linux-server.lab.local@LAB.LOCAL`
- Test Principal: `testuser@LAB.LOCAL` (with password `Password123!`)

---

## Deployment Steps

Follow these steps to deploy and run the lab:

### 1. Boot and Provision the Domain Controller
The Active Directory Domain Controller must be set up first. Promoting a Domain Controller requires a reboot. Our script registers a post-boot startup task that automatically completes the setup (user creation, SPN mapping, and keytab export) after the reboot finishes:

```bash
# Start the AD server (installs roles, promotes forest, reboots, and runs post-boot tasks)
vagrant up ad-server
```

*Note: Once the server finishes rebooting, it takes about 1-2 minutes for the AD services to start in the background, after which the startup script will automatically generate and save `linux-server.keytab` into your local project directory.*

### 2. Boot the Linux Nodes
After the keytab has been exported to the shared folder, boot the Linux client and server:

```bash
vagrant up linux-server linux-client
```

This will automatically configure:
- Hosts files and name resolution
- `/etc/krb5.conf`
- SSHD configs on the server (enabling GSSAPIAuthentication)
- SSH client configs on the client (delegation enabled)
- Local `testuser` accounts

---

## Verification Guide

Follow these steps to verify GSSAPI logon using a Kerberos ticket:

### Step 1: Access the Client
Log into `linux-client` and switch to the `testuser` account:
```bash
vagrant ssh linux-client
sudo su - testuser
```

### Step 2: Request a TGT
Run `kinit` to obtain a Ticket-Granting Ticket from the Windows Server KDC:
```bash
kinit testuser@LAB.LOCAL
```
- Enter Password: `Password123!`

Confirm you have received the ticket:
```bash
klist
```
*Expected output:*
```
Ticket cache: FILE:/tmp/krb5cc_1001
Default principal: testuser@LAB.LOCAL

Valid starting       Expires              Service principal
06/20/2026 12:00:00  06/21/2026 22:00:00  krbtgt/LAB.LOCAL@LAB.LOCAL
```

### Step 3: Login to Server via GSSAPI SSH
SSH into the server node using the Kerberos ticket. Note that you will not be prompted for a password:
```bash
ssh testuser@linux-server.lab.local
```

### Step 4: Verify Credential Delegation
On the server shell, run:
```bash
klist
```
*Expected output:*
You should see your forwarded Kerberos ticket. This confirms that GSSAPI not only authenticated you but also securely delegated your credentials.

---

## Teardown Steps

To clean up all resources and delete the lab virtual machines, run the following:

### 1. Destroy the Virtual Machines
Force shutdown and delete the virtual machines and associated virtual disks:
```bash
vagrant destroy -f
```

### 2. Clean Up Generated Artifacts
Remove the generated Kerberos keytab file from the project directory:
```bash
# PowerShell
Remove-Item -Force linux-server.keytab

# Bash
rm -f linux-server.keytab
```

### 3. Clear Vagrant State (Optional)
If you wish to do a completely fresh re-initialization of the lab:
```bash
# PowerShell
Remove-Item -Recurse -Force .vagrant

# Bash
rm -rf .vagrant/
```
