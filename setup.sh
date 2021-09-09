echo "Installing OpenLDAP"
export basedir=${pwd}
export LLAND=$(dirname ${basedir})
echo ${LLAND}

echo "Remove Existing Installation"
# Reload
sudo yum erase -y symas-openldap-servers.x86_64 symas-openldap.x86_64
sudo yum erase -y openldap-clients openldap-servers
sudo rm -rf /etc/openldap
sudo rm -rf /var/lib/ldap/data.mdb
sudo rm -rf /var/lib/ldap/DB_CONFIG
sudo rm -rf /var/lib/ldap/lock.mdb


echo "Adding Microsoft Repo"
sudo rm -rf ${LLAND}/rhui-microsoft-azure-rhel8.config
sudo wget https://rhelimage.blob.core.windows.net/repositories/rhui-microsoft-azure-rhel8.config
sudo yum --config=${LLAND}/rhui-microsoft-azure-rhel8.config install rhui-azure-rhel8
sudo rm -rf ${LLAND}/rhui-microsoft-azure-rhel8.config

echo "Updating Repo"
# Update repo
sudo yum update

echo "Install Pre-Req Packages"

# Install
sudo yum install openldap-clients -y
sudo yum install openldap-servers sssd openssl-perl -y
sudo systemctl start slapd
sudo systemctl enable slapd

echo "Starting LDAP Configuration"
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f ${LLAND}/config1.ldif
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f ${LLAND}/config2.ldif

sudo cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG
sudo chown -R ldap:ldap /var/lib/ldap/DB_CONFIG
sudo systemctl restart slapd

echo "Adding schemas"

sudo ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif 
sudo ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif
sudo ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif

echo "Adding MemberOf Overlay"
# Add memberOf overlay
sudo ldapadd -Y EXTERNAL -H ldapi:/// -f ${LLAND}/memberof.ldif
sudo ldapmodify -Q -Y EXTERNAL -H ldapi:/// -f ${LLAND}/refint1.ldif
sudo ldapadd -Q -Y EXTERNAL -H ldapi:/// -f ${LLAND}/refint2.ldif


echo "Adding Groups and Users"
# Add Base
sudo ldapadd -x -D cn=admin,dc=domain,dc=com -w secret -f ${LLAND}/base.ldif
sudo ldapadd -x -D cn=admin,dc=domain,dc=com -w secret -f ${LLAND}/testuser.ldif
sudo ldapadd -x -D cn=admin,dc=domain,dc=com -w secret -f ${LLAND}/groups.ldif

sudo service slapd restart

# Setup SSSD
sudo cp ${LLAND}/sssd.conf /etc/sssd/sssd.conf
sudo chmod 700 /etc/sssd/sssd.conf
sudo systemctl restart sssd
sudo systemctl enable --now oddjobd
systemctl enable --now sssd

#Installs SSSD Service for OpenLDAP
# Source https://wiki.archlinux.org/title/LDAP_authentication#Online_and_Offline_Authentication_with_SSSD
#
#
#


echo "Configuring SSSD and PAM with OpenLDAP"
sudo systemctl stop firewalld
sleep 10
sudo systemctl disable firewalld


echo "Adding Groups Used for LDAP Tree to Linux"

if grep -q sasusers /etc/group
   then
        echo "sasusers Group Already Exists"
   else
	sudo groupadd -g 10000 sasusers
fi

if grep -q Testers /etc/group
   then
        echo "Testers Group Already Eexists"
   else
	sudo groupadd -g 10001 Testers
fi

echo  "Completed Added sasusers and Testers"



echo "Installing Pre-req Packages"
sudo yum install nss-pam-ldapd -y
echo "Done Installing Pre-req Packages"
sleep 5

echo "Creating Backups"

if [[ -d "${LLAND}/sssd_update" ]]
   then
        sudo rm -rf ${LLAND}/sssd_update
        sudo mkdir ${LLAND}/sssd_update
   else
        sudo mkdir ${LLAND}/sssd_update

fi


sudo cp /etc/nsswitch.conf ${LLAND}/sssd_update/.
sudo cp /etc/nslcd.conf ${LLAND}/sssd_update/.
sudo cp /etc/pam.d/system-auth ${LLAND}/sssd_update/.
sudo cp /etc/pam.d/password-auth ${LLAND}/sssd_update/.
sudo cp /etc/pam.d/su ${LLAND}/sssd_update/.
sudo cp /etc/pam.d/su-l ${LLAND}/sssd_update/.
sudo cp /etc/pam.d/passwd ${LLAND}/sssd_update/.
sudo cp /etc/pam.d/sudo ${LLAND}/sssd_update/.
sudo cp /etc/openldap/ldap.conf ${LLAND}/sssd_update/.
sudo cp /etc/sssd/sssd.conf ${LLAND}/sssd_update/.
sudo cp /etc/nscd.conf ${LLAND}/sssd_update/.

echo "Finished Creating Backups"

echo "Modifying Configurations"

echo "Updating Hosts"
IP=$(hostname -I)
sed -i "$ a\\${IP} ldap.domain.com" /etc/hosts

echo "Updating nsswitch.conf"
sed -i 's/^passwd\:.*/passwd\:  files  ldap  sss  systemd/g' /etc/nsswitch.conf
sed -i 's/^shadow\:.*/shadow\:  files  ldap  sss/g' /etc/nsswitch.conf
sed -i 's/^group\:.*/group\:  files  ldap  sss  systemd/g' /etc/nsswitch.conf
#sed -i '/^automount\:.*/a sudoers:  files  sss' /etc/nsswitch.conf


echo "Updating nslcd.conf"
sed -i 's/^uri ldap\:.*/uri ldap\:\/\/ldap.domain.com/g' /etc/nslcd.conf
sed -i 's/^#ldap_version 3/ldap_version 3/g' /etc/nslcd.conf
sed -i 's/^base dc=example,dc=com/base dc=domain,dc=com/g' /etc/nslcd.conf
sed -i 's/^#binddn cn=proxyuser,dc=example,dc=com/binddn cn=admin,dc=domain,dc=com/g' /etc/nslcd.conf
sed -i 's/^#bindpw secret/bindpw secret/g' /etc/nslcd.conf
sed -i 's/^#base   group  ou=Groups,dc=example,dc=com/base   group  ou=groups,dc=domain,dc=com/g' /etc/nslcd.conf
sed -i 's/^#base   passwd ou=People,dc=example,dc=com/base   passwd ou=users,dc=domain,dc=com/g' /etc/nslcd.conf


echo "Updating ldap.conf"
sed -i 's/^#BASE.*/BASE    dc=domain,dc=com/g' /etc/openldap/ldap.conf
sed -i 's/^#URI.*/URI     ldap:\/\/ldap.domain.com/g' /etc/openldap/ldap.conf
sed -i 's/^SASL_NOCANON.*/#SASL_NOCANON\t on/g' /etc/openldap/ldap.conf

sudo systemctl start nslcd.service
sudo systemctl enable nslcd.service


echo "Updating system-auth"
sed -i '/^# User changes .*/a auth      sufficient pam_ldap.so' /etc/pam.d/system-auth
sed -i '/^auth.*pam_ldap.so/a auth sufficient pam_sss.so forward_pass' /etc/pam.d/system-auth
sed -i '/auth.*pam_env.so/d' /etc/pam.d/system-auth
sed -i '/^auth.*nullok/a auth        required      pam_env.so' /etc/pam.d/system-auth

sed -i '/^account.*pam_unix.so/i account   sufficient pam_ldap.so' /etc/pam.d/system-auth
sed -i '/^account.*pam_unix.so/i account \[default=bad success=ok user_unknown=ignore authinfo_unavail=ignore\] pam_sss.so' /etc/pam.d/system-auth

sed -i '/^password.*authtok_type=/i password   sufficient pam_ldap.so' /etc/pam.d/system-auth
sed -i '/^password.*authtok_type=/i password sufficient pam_sss.so use_authtok' /etc/pam.d/system-auth

sed -i '/^session.*pam_unix.so/a session   optional  pam_ldap.so' /etc/pam.d/system-auth
sed -i '/^session.*revoke/i session required pam_mkhomedir.so skel=\/etc\/skel\/ umask=0077' /etc/pam.d/system-auth

echo "Updating password-auth"
sed -i '/^# User changes .*/a auth      sufficient pam_ldap.so' /etc/pam.d/password-auth
sed -i '/^auth.*pam_ldap.so/a auth sufficient pam_sss.so forward_pass' /etc/pam.d/password-auth

sed -i '/^account.*pam_unix.so/i account   sufficient pam_ldap.so' /etc/pam.d/password-auth
sed -i '/^account.*pam_unix.so/i account \[default=bad success=ok user_unknown=ignore authinfo_unavail=ignore\] pam_sss.so' /etc/pam.d/password-auth
sed -i '/^session.*pam_unix.so/a session   optional  pam_ldap.so' /etc/pam.d/password-auth

echo "Updating sssd.conf"
sed -i '/access_provider = ldap/d' /etc/sssd/sssd.conf
sed -i 's/^enumerate.*/enumerate = True/g' /etc/sssd/sssd.conf
sed -i 's/^ldap_schema.*/ldap_schema = rfc2307/g' /etc/sssd/sssd.conf
sed -i 's/^ldap_group_member.*/ldap_group_member = memberOf/g' /etc/sssd/sssd.conf
sed -i 's/^services = nss, pam/services = nss, pam, sudo/'g /etc/sssd/sssd.conf

sudo chmod 600 /etc/sssd/sssd.conf

echo "Updating nscd.conf"
sed -i 's/enable-cache.*passwd.*yes/enable-cache\t\tpasswd\t\tno/g' /etc/nscd.conf
sed -i 's/enable-cache\t\tgroup.*yes/enable-cache\t\tgroup\t\tno/g' /etc/nscd.conf
sed -i 's/enable-cache.*netgroup.*yes/enable-cache\t\tnetgroup\tno/g' /etc/nscd.conf


echo "Updating su"
sed -i '/^.*pam_rootok.so/a auth\t\tsufficient\tpam_ldap.so' /etc/pam.d/su
sed -i '/.*pam_ldap.so/a auth\t\tsufficient\tpam_sss.so\tforward_pass' /etc/pam.d/su
sed -i '/^account.*quiet/i account\t\tsufficient\tpam_ldap.so' /etc/pam.d/su
sed -i '/^account.*pam_ldap.so/a account\t\t[default=bad success=ok user_unknown=ignore authinfo_unavail=ignore] pam_sss.so' /etc/pam.d/su
sed -i '/^session.*system-auth/i session\t\tsufficient\tpam_ldap.so' /etc/pam.d/su
sed -i '/^session.*pam_xauth.so/a session\t\toptional\tpam_sss.so' /etc/pam.d/su


echo "updating su-l"
#sed -i '/^auth.*su/a auth		sufficient	pam_ldap.so' /etc/pam.d/su-l
sed -i '/^session.*revoke/i session\t\trequired\tpam_mkhomedir.so skel=/etc/skel umask=0022' /etc/pam.d/su-l

echo "Updating passwd"
sed -i '/^# This tool only uses the password stack./a password sufficient pam_ldap.so' /etc/pam.d/passwd
sed -i '/pam_ldap.so/a password   sufficient   pam_sss.so' /etc/pam.d/passwd


echo "Updating Sudo"
sed -i '/^auth.*/i auth       sufficient   pam_sss.so' /etc/pam.d/sudo


echo "Finished Configuration....."


echo "Restarting Services......"
sudo systemctl restart sssd
sleep 10
sudo systemctl enable sssd
sleep 10

