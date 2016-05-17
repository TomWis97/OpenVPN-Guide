Installing OpenVPN on CentOS with Active Directory authentication.

This guide assumes that you have experience with CentOS. Before continuing, make sure your OS is up-to-date and has a static IP.
The goal of this guide is to have an working OpenVPN server which has certificate authentication and username/password authentication against Active Directory.

This guide makes to following assumptions:
* Local subnet is 10.0.0.0/24
* VPN subnet is 10.1.1.0/24
* Active directory domain is `vpn.lab`.
* The DC is at IP 10.0.0.3 and it's hostname is "DC".
* Your router is capable of adding static routes. (If not, you'll have to configure NAT overload.)
* Windows Server 2012 R2 for DC. But it shouldn't matter that much.
* CentOS 7 with minimal install.

## Getting OpenVPN
You can choose to get OpenVPN's source and compile it yourself. Alternatively, you can use the [EPEL](https://fedoraproject.org/wiki/EPEL) repository:
`yum install epel-release`

Now that we have the repository configured, it's time to install OpenVPN and easyrsa (for certificates).
`yum install openvpn easy-rsa`

## Setting up Easy-RSA
We're going to use easy-rsa for creating certificates for authentication. To keep all the configuration files (and certificates) in one directory, copy easy-rsa to /etc/openvpn.
`cp -r /usr/share/easy-rsa/2.0 /etc/openvpn/easy-rsa`

TODO IMAGE HERE

The next step is to setup easy-rsa. Start with setting the certificate information:
`vi /etc/openvpn/easy-rsa/vars`
You'll need to edit the values for the KEY_* variables (line 64 - 69).

With those variables set, it's time to init the PKI: (Note the full stop before ./vars!)
````
. ./vars
./clean-all
./build-ca
````

TODO IMAGE HERE

Now we can create the server certificate:
````
./build-key-server server
````
Accept the default values. Keep the password empty, sign the certificate and commit.
Create a certificate for the first client:
````
./build-key client1
````
We'll automate creating a new client certificate once everything is working.
Create the 2048 bit Diffie-Hellman parameters:
````
./build-dh
````
Generate a TLS authentication key:
````
cd /etc/openvpn/easy-rsa/keys
openvpn --genkey --secret ta.key
````

## Configure OpenVPN
We're going to user OpenVPN's sample configuration as base. To keep things clear, copy the sample config (server and client) to /etc/openvpn/: (Note: Change the path to match your OpenVPN version number!)
````
cp /usr/share/doc/openvpn-2.3.10/sample/sample-config-files/{server.conf,client.conf} /etc/openvpn/
````
Now it's time to edit the server configuration:
````
vi /etc/openvpn/server.conf
````
Make the following changes:
* `local` Set this to the machine's static IP.
* `port` You can change the port for security by obscurity purposes
* `proto` Set the protocol for this OpenVPN instance. It's recommended to choose UDP because TCP might create a lot of overhead, especially on poor connections.
* `ca`, `cert`, `key`, `dh` Set these ones to refer to the server files in the easy-rsa directory. For example: `ca easy-rsa/keys/ca.crt` and `cert easy-rsa/keys/server.crt`.
* Uncomment `topology subnet`.
* Set the subnet at `server`. Example: `server 10.1.1.0 255.255.255.0`.
* The `push` lines are for pushing a configuration command to the clients. Add the following lines:
    * Add `push "route 10.0.0.0 255.255.255.0"` *Replace the subnet with your home subnet*.
    * Add `push "dhcp-option DNS 10.0.0.3"`.
    * Add `push "dhcp-option DOMAIN vpn.lab"`.
    * Uncomment `push "redirect-gateway def1 bypass-dhcp"`
* Uncomment `client-to-client` to enable communication between VPN clients.
* Uncomment `tls-auth ta.key 0`. Change the path to the keys directory. Example `tls-auth easy-rsa/keys/ca.crt 0`.
* Uncomment `user nobody` and `group nobody` *(On some distro's the group should be "nogroup".)
* Add the line `plugin /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn`

The server should be configured now. Let's move on to the client:
````
vi /etc/openvpn/client.conf
````
Make the following changes:
* Comment the `proto` directive. We'll set that later. This makes running a multi-daemon server where you have one daemon for UDP and another one for TCP easier.
* Set the `remote` server address, port and procol. Example: `remote contoso.com 1234 udp`.
* Comment out the `ca`, `cert`, `key` directives. We're going to put those inline.
* Add the lines `auth-user-pass` and `key-direction 1`.

Make sure your router has a static route for the VPN subnet set. Don't forget to port forward.

Because the OS is going to do some routing, you'll need to enable routing. Add the line `net.ipv4.ip_forward = 1` to /etc/sysctl.conf. Activate this by running `sysctl -p`.

Configure the firewall. Allow OpenVPN traffic and allow routing between networks. Don't forget to change the port/protocol if neccessary. Don't forget to change the names (eno16777736 in this example).
````
firewall-cmd --zone=public --add-port=1194/udp --permanent
firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i eno16777736 -o tun0 -j ACCEPT
firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i tun0 -o eno16777736 -j ACCEPT
systemctl restart firewalld
````

The configuration for OpenVPN should be almost done by now.

## Active Directory Integration
I'm going to use PAM for AD integration. This way we can use Kerberos and it's well-documented at the Arch Wiki: https://wiki.archlinux.org/index.php/Active_Directory_Integration
This guide is greatly based on this wiki. I made some changes to make it work with CentOS 7.

GPO configuration:
> It may be necessary to disable Digital Sign Communication (Always) in the AD group policies. Dive into:
> `Local policies` -> `Security policies` -> `Microsoft Network Server` -> `Digital sign communication (Always)` -> activate define this policy and use the disable radio button.
> If you use Windows Server 2008 R2, you need to modify that in GPO for Default Domain `Controller Policy` -> `Computer Settings` -> `Policies` -> `Windows Settings` -> `Security Settings` -> `Local Policies` -> `Security Options` -> Microsoft network client: Digitally sign communications (always)

You need to configure NTP seperately if your machine doesn't get it's time from the hypervisor.
Install `samba`, `pam_krb5`, `samba-winbind`, `samba-winbind-clients`, `krb5-workstation`.

Now overwrite /etc/krb5.conf with the following config. (Yes, taken from the wiki.) Don't forget to put your own domain here. Mind the capitalisation.
````
[libdefaults]
    default_realm       = VPN.LAB
	clockskew    	    = 300
	ticket_lifetime	    = 1d
    forwardable         = true
    proxiable           = true
    dns_lookup_realm    = true
    dns_lookup_kdc      = true

[realms]
	VPN.LAB = {
		kdc 	        = DC.VPN.LAB
        admin_server    = DC.VPN.LAB
		default_domain  = VPN.LAB
	}

[domain_realm]
    .kerberos.server    = VPN.LAB
	.vpn.lab            = VPN.LAB
	vpn.lab             = VPN.LAB
	VPN	                = VPN.LAB

[appdefaults]
	pam = {
	    ticket_lifetime 	= 1d
	    renew_lifetime 		= 1d
	    forwardable 		= true
	    proxiable 		    = false
	    retain_after_close 	= false
	    minimum_uid 		= 0
	    debug 			    = false
	}

[logging]
	default 		= FILE:/var/log/krb5libs.log
	kdc 			= FILE:/var/log/kdc.log
    admin_server    = FILE:/var/log/kadmind.log
````
Create a Kerberos ticket and check if you got one:
````
kinit administrator@VPN.LAB
klist
````
It's a great idea to only accept users who are member of a group. You need to get the SID of that group. User Powershell for this:
````
Get-ADGroup "VPN Users"
````
Edit /etc/security/pam_winbind.conf. Replace the contents with this: (Don't forget to replace the SID!)
````
[global]
  debug = no
  debug_state = no
  try_first_pass = yes
  krb5_auth = yes
  krb5_cache_type = FILE
  cached_login = yes
  silent = no
  mkhomedir = yes
  require_membership_of = S-1-5-21-994948881-1046571352-2957874562-1603
````
Replace the /etc/samba/smb.conf with this:
````
[Global]
  netbios name = OPENVPN
  workgroup = VPN
  realm = VPN.LAB
  server string = %h OpenVPN Server
  security = ads
  encrypt passwords = yes
  password server = DC.vpn.lab

  idmap config * : backend = rid
  idmap config * : range = 10000-20000

  winbind use default domain = Yes
  winbind enum users = Yes
  winbind enum groups = Yes
  winbind nested groups = Yes
  winbind separator = +
  winbind refresh tickets = yes
  winbind offline logon = yes
  winbind cache time = 300

  template shell = /sbin/nologin
  kerberos method = secrets only

  preferred master = no
  dns proxy = no
  wins server = DC.vpn.lab
  wins proxy = no

  inherit acls = Yes
  map acl inherit = Yes
  acl group control = yes

  load printers = no
  debug level = 3
  use sendfile = no
````
Change the following directives:
* `netbios name`: your hostname
* `workgroup`: Your netbios domain
* `realm`: Your domain (capitalisation!)
* `password server`
* `wins server`

Join CentOS to the domain:
````
net ads join -U Administrator
````
It might complain about being unable to perform DNS Update. This doesn't matter.
If you check ADUC, you'll see the OpenVPN server.
Enable and start the services:
````
systemctl enable {smb,nmb,winbind}
systemctl start {smb,nmb,winbind}
````
Configure nsswitch by editing /etc/nsswitch.conf by appending "winbind" to the `passwd`, `shadow`, `group` lines.

TODO IMAGE HERE

Now we can check if Winbind is able to query AD. This should return a list of AD users: `wbinfo -u`. Check samba's communication with AD: `net ads info` and `net ads status -U administrator`.

Now it's time to configure PAM. Create /etc/pam.d/openvpn with the following contents:
````
#%PAM-1.0
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        sufficient    pam_winbind.so cached_login use_first_pass
auth        required      pam_deny.so

account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     [default=bad success=ok user_unknown=ignore] pam_winbind.so cached_login
account     required      pam_permit.so
````
This allows local users and AD users to login to the VPN. That should be it for AD integration.

## Testing!

To make it a bit easier to generate a .ovpn file for a device, you can use this script. Put this in /etc/openvpn/new-client.
````
#!/bin/bash
# This is just a quick and dirty script. Feel free to improve it on GitHub. :)
# This script has little to none safety checks.
# Usage: ./new-client name
# Where name doesn't contain any special characters like spaces.
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi
echo "Creating a config for $1."
cd /etc/openvpn/easy-rsa
. ./vars
./build-key $1
cd ..
cp client.conf $1.ovpn
echo "<ca>" >> $1.ovpn
cat easy-rsa/keys/ca.crt >> $1.ovpn
echo "</ca>" >> $1.ovpn
echo "<cert>" >> $1.ovpn
awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' easy-rsa/keys/$1.crt >> $1.ovpn
echo "</cert>" >> $1.ovpn
echo "<key>" >> $1.ovpn
cat easy-rsa/keys/$1.key >> $1.ovpn
echo "</key>" >> $1.ovpn
echo "<tls-auth>" >> $1.ovpn
cat easy-rsa/keys/ta.key >> $1.ovpn
echo "</tls-auth>" >> $1.ovpn
echo
echo "Configuration saved as `pwd`/$1.ovpn."
echo "Warning! This file contains private keys. You should move it using a secure channel to your device and delete the file from this server."
````
It's nowhere near perfect, but it does what it's supposed to do. Remember to chmod +x the file.
Create a client config by running `/etc/openvpn/new-client testclient` as root.

This should be it! Continue by starting openvpn in a console. Remind to start openvpn as root. (It needs to be able to read the keys.)
````
cd /etc/openvpn
openvpn server.conf
````
On your client (a Windows 10 VM in this case), install openvpn. Save the config to C:\Program Files\OpenVPN\config\testclient.ovpn. In order for OpenVPN to change the default gateway, the client has to be running as Administrator. Fire up the client and connect. Enter your username and password and click connect. It should be working.

## Sources
https://wiki.archlinux.org/index.php/Active_Directory_Integration
https://www.linuxsysadmintutorials.com/setup-pam-authentication-with-openvpns-auth-pam-module.html
https://www.samba.org/samba/docs/man/manpages/pam_winbind.conf.5.html
