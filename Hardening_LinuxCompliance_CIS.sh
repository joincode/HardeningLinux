#/bin/bash
###############################################################################
# Descrição: Script Hardening em Sistemas Operacionais Linux.
#------------------------------------------------------------------------------
# Usabilidade:
# - Efetuar Hardening baseado em normas utilizadas pelo CIS 2.1.1
# - Utilizado no CentOs 6.9 | CentOs 7 | RHEL6 | RHEL 7
# - ./Hardening_LinuxCompliance_CIS.sh
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# ID              Date   version
# Roberto.Lima 2017.10.26 0.1  
#------------------------------------------------------------------------------
###############################################################################
#set -x       #Descommentar essa linha para ver em modo debug o script
###############################################################################
#Após análise do ambiente, a aplicacao de conformidade deverá ser exeutada em modo root
#Verificar se o Script está sendo executado como Root#
if [ "$EUID" -ne 0 ]
  then echo "Favor executar como root"
  exit
fi
echo "Iniciando Script de Conformidade "
mkdir -p /root/Auditoria/
###############################################################################
#Controle de variaveis de ambiente
HOST=`hostname`
DATA=`date +"%d%m%Y-%H%M"`
LOG='/root/Auditoria/Auditoria-'$HOST'-'$DATA'.csv'
#criar aquivo de Log para análise de ambiente
touch $LOG
MP=`echo "manual procedure"`
################################################################################
echo "Iniciando Script de Compliance" >> $LOG
clear
    echo "Initial Setup" >> $LOG
    echo "1.1	Filesystem Configuration">> $LOG
        echo "1.1.1	Disable unused filesystems">> $LOG
            CONTROL="1.1.1.1 Ensure mounting of cramfs filesystems is disabled"
                echo  "$CONTROL,pass,Scored">> $LOG
            CONTROL="1.1.1.2 Ensure mounting of freevxfs filesystems is disabled"
                 echo "$CONTROL,pass,Scored">> $LOG
            CONTROL="1.1.1.3 Ensure mounting of jffs2 filesystems is disabled"
                 echo "$CONTROL,pass,Scored">> $LOG
            CONTROL="1.1.1.4 Ensure mounting of hfs filesystems is disabled"
                 echo "$CONTROL,pass,Scored">> $LOG
            CONTROL="1.1.1.5 Ensure mounting of hfsplus filesystems is disabled"
                 echo "$CONTROL,pass,Scored">> $LOG
            CONTROL="1.1.1.6 Ensure mounting of squashfs filesystems is disabled"
                 echo "$CONTROL,pass,Scored">> $LOG
            CONTROL="1.1.1.7 Ensure mounting of udf filesystems is disabled"
                 echo "$CONTROL,pass,Scored">> $LOG
            CONTROL="1.1.1.8 Ensure mounting of FAT filesystems is disabled"
                 echo "$CONTROL,pass,Scored">> $LOG
echo "/etc/modprobe.d/CIS.conf"
if [ "$?" == "0" ]; then
  rm -f /etc/modprobe.d/CIS.conf
  else
  touch /etc/modprobe.d/CIS.conf
fi

CISCONF="/etc/modprobe.d/CIS.conf"
        echo "install cramfs /bin/true"     >>$CISCONF
        echo "install freevxfs /bin/true"   >>$CISCONF
        echo "install jffs2 /bin/true"      >>$CISCONF
        echo "install hfs /bin/true"        >>$CISCONF
        echo "install hfsplus /bin/true"    >>$CISCONF
        echo "install squashfs /bin/true"   >>$CISCONF
        echo "install udf /bin/true"        >>$CISCONF
        echo "install vfat /bin/true"       >>$CISCONF

#these are highly suggested whith manual control
        CONTROL="1.1.2	Ensure separate partition exists for /tmp"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.3	Ensure nodev option set on /tmp partition"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.4	Ensure nosuid option set on /tmp partition" 
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.5	Ensure noexec option set on /tmp partition"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.6	Ensure separate partition exists for /var"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.7	Ensure separate partition exists for /var/tmp"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.8	Ensure nodev option set on /var/tmp partition"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.9	Ensure nosuid option set on /var/tmp partition"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.10	Ensure noexec option set on /var/tmp partition"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.11	Ensure separate partition exists for /var/log"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.12	Ensure separate partition exists for /var/log/audit"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.13	Ensure separate partition exists for /home"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.14	Ensure nodev option set on /home partition"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.15	Ensure nodev option set on /dev/shm partition"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.16	Ensure nosuid option set on /dev/shm partition"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.17	Ensure noexec option set on /dev/shm partition"
            echo "$CONTROL,$MP,Scored">> $LOG
        CONTROL="1.1.18	Ensure nodev option set on removable media partitions"
            echo "$CONTROL,$MP,Not Scored">> $LOG
        CONTROL="1.1.19	Ensure nosuid option set on removable media partitions"
            echo "$CONTROL,$MP,Not Scored">> $LOG
        CONTROL="1.1.20	Ensure noexec option set on removable media partitions"
            echo "$CONTROL,$MP,Not Scored">> $LOG
        CONTROL="1.1.21	Ensure sticky bit is set on all world-writable directories"
            echo "$CONTROL,$MP,Not Scored">> $LOG
        CONTROL="1.1.22	Disable Automounting"
            echo "$CONTROL,$MP,Scored">> $LOG

#-------------------------------------------------------------------------------
#   partition        noexec      nodev      nosuid      location         
#-------------------------------------------------------------------------------
#    /	                no	        no	       no	        /
#    /tmp	            yes	        yes        yes	        /tmp
#    /var            	opt	        yes        yes	        /var
#    /var/log	        opt	        yes        yes	        /var/log
#    /var/log/audit	    opt	        yes	       yes	        /var/log/audit
#    /var/tmp	        yes	        yes        yes      	/tmp
#    /home           	opt     	yes	       yes	        /home
#    /run/shm        	yes     	yes	       yes	        /run/shm
#    External Media	    yes     	yes        yes	        /dev/*
#-------------------------------------------------------------------------------
# these scheme are highly suggested

echo "1.2 Configure Software Updates"
echo "1.2.1	Ensure package manager repositories are configured (Not Scored)"
echo "1.2.2	Ensure gpgcheck is globally activated (Scored)"
    sed -i 's/gpgcheck=0/gpgcheck=1/' /etc/yum.conf
#1.2.3	Ensure GPG keys are configured (Not Scored)
#efetuar verificação de chaves para o CentOs6 e 7
gpg --quiet --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6

#1.2.4	Ensure Red Hat Network or Subscription Manager connection is configured (Not Scored)
#1.2.5	Disable the rhnsd Daemon (Not Scored)
echo "1.3 Filesystem Integrity Checking"
#1.3.1	Ensure AIDE is installed (Scored)
#1.3.2	Ensure filesystem integrity is regularly checked (Scored)
#1.4	Secure Boot Settings
#1.4.1	Ensure permissions on bootloader config are configured (Scored)
#1.4.2	Ensure bootloader password is set (Scored)
#1.4.3	Ensure authentication required for single user mode (Not Scored)
#1.5	Additional Process Hardening
#1.5.1	Ensure core dumps are restricted (Scored)
#1.5.2	Ensure XD/NX support is enabled (Not Scored)
#1.5.3	Ensure address space layout randomization (ASLR) is enabled (Scored)
#1.5.4	Ensure prelink is disabled (Scored)
#1.6	Mandatory Access Control
#1.6.1	Configure SELinux
#1.6.1.1	Ensure SELinux is not disabled in bootloader configuration (Scored)
#1.6.1.2	Ensure the SELinux state is enforcing (Scored)
#1.6.1.3	Ensure SELinux policy is configured (Scored)
#1.6.1.4	Ensure SETroubleshoot is not installed (Scored)
#1.6.1.5	Ensure the MCS Translation Service (mcstrans) is not installed (Scored)
#1.6.1.6	Ensure no unconfined daemons exist (Scored)
#1.6.2	Ensure SELinux is installed (Scored)
#1.7	Warning Banners
#1.7.1	Command Line Warning Banners
#1.7.1.1	Ensure message of the day is configured properly (Scored)
#1.7.1.2	Ensure local login warning banner is configured properly (Not Scored)
#1.7.1.3	Ensure remote login warning banner is configured properly (Not Scored)
#1.7.1.4	Ensure permissions on /etc/motd are configured (Not Scored)
#1.7.1.5	Ensure permissions on /etc/issue are configured (Scored)
#1.7.1.6	Ensure permissions on /etc/issue.net are configured (Not Scored)
#1.7.2	Ensure GDM login banner is configured (Scored)
#1.8	Ensure updates, patches, and additional security software are installed (Not Scored)
echo "2	Services"
#2.1	inetd Services
#2.1.1	Ensure chargen services are not enabled (Scored)
#2.1.2	Ensure daytime services are not enabled (Scored)
#2.1.3	Ensure discard services are not enabled (Scored)
#2.1.4	Ensure echo services are not enabled (Scored)
#2.1.5	Ensure time services are not enabled (Scored)
#2.1.6	Ensure tftp server is not enabled (Scored)
#2.1.7	Ensure xinetd is not enabled (Scored)
#2.2	Special Purpose Services
#2.2.1	Time Synchronization
#2.2.1.1	Ensure time synchronization is in use (Not Scored)
#2.2.1.2	Ensure ntp is configured (Scored)
#2.2.1.3	Ensure chrony is configured (Scored)
#2.2.2	Ensure X Window System is not installed (Scored)
#2.2.3	Ensure Avahi Server is not enabled (Scored)
#2.2.4	Ensure CUPS is not enabled (Scored)
#2.2.5	Ensure DHCP Server is not enabled (Scored)
#2.2.6	Ensure LDAP server is not enabled (Scored)
#2.2.7	Ensure NFS and RPC are not enabled (Scored)
#2.2.8	Ensure DNS Server is not enabled (Scored)
#2.2.9	Ensure FTP Server is not enabled (Scored)
#2.2.10	Ensure HTTP server is not enabled (Scored)
#2.2.11	Ensure IMAP and POP3 server is not enabled (Scored)
#2.2.12	Ensure Samba is not enabled (Scored)
#2.2.13	Ensure HTTP Proxy Server is not enabled (Scored)
#2.2.14	Ensure SNMP Server is not enabled (Scored)
#2.2.15	Ensure mail transfer agent is configured for local-only mode (Scored)
#2.2.16	Ensure NIS Server is not enabled (Scored)
#2.2.17	Ensure rsh server is not enabled (Scored)
#2.2.18	Ensure talk server is not enabled (Scored)
#2.2.19	Ensure telnet server is not enabled (Scored)
#2.2.20	Ensure tftp server is not enabled (Scored)
#2.2.21	Ensure rsync service is not enabled (Scored)
#2.3	Service Clients
#2.3.1	Ensure NIS Client is not installed (Scored)
#2.3.2	Ensure rsh client is not installed (Scored)
#2.3.3	Ensure talk client is not installed (Scored)
#2.3.4	Ensure telnet client is not installed (Scored)
#2.3.5	Ensure LDAP client is not installed (Scored)
#3	Network Configuration
#3.1	Network Parameters (Host Only)
#3.1.1	Ensure IP forwarding is disabled (Scored)
#3.1.2	Ensure packet redirect sending is disabled (Scored)
#3.2	Network Parameters (Host and Router)
#3.2.1	Ensure source routed packets are not accepted (Scored)
#3.2.2	Ensure ICMP redirects are not accepted (Scored)
#3.2.3	Ensure secure ICMP redirects are not accepted (Scored)
#3.2.4	Ensure suspicious packets are logged (Scored)
#3.2.5	Ensure broadcast ICMP requests are ignored (Scored)
#3.2.6	Ensure bogus ICMP responses are ignored (Scored)
#3.2.7	Ensure Reverse Path Filtering is enabled (Scored)
#3.2.8	Ensure TCP SYN Cookies is enabled (Scored)
#3.3	IPv6
#3.3.1	Ensure IPv6 router advertisements are not accepted (Scored)
#3.3.2	Ensure IPv6 redirects are not accepted (Scored)
#3.3.3	Ensure IPv6 is disabled (Not Scored)
#3.4	TCP Wrappers
#3.4.1	Ensure TCP Wrappers is installed (Scored)
#3.4.2	Ensure /etc/hosts.allow is configured (Scored)
#3.4.3	Ensure /etc/hosts.deny is configured (Scored)
#3.4.4	Ensure permissions on /etc/hosts.allow are configured (Scored)
#3.4.5	Ensure permissions on /etc/hosts.deny are 644 (Scored)
#3.5	Uncommon Network Protocols
#3.5.1	Ensure DCCP is disabled (Not Scored)
#3.5.2	Ensure SCTP is disabled (Not Scored)
#3.5.3	Ensure RDS is disabled (Not Scored)
#3.5.4	Ensure TIPC is disabled (Not Scored)
#3.6	Firewall Configuration
#3.6.1	Ensure iptables is installed (Scored)
#3.6.2	Ensure default deny firewall policy (Scored)
#3.6.3	Ensure loopback traffic is configured (Scored)
#3.6.4	Ensure outbound and established connections are configured (Not Scored)
#3.6.5	Ensure firewall rules exist for all open ports (Scored)
#3.7	Ensure wireless interfaces are disabled (Not Scored)
echo "4	Logging and Auditing"
echo "4.1	Configure System Accounting (auditd)"
#4.1.1	Configure Data Retention
#4.1.1.1	Ensure audit log storage size is configured (Not Scored)
#4.1.1.2	Ensure system is disabled when audit logs are full (Scored)
#4.1.1.3	Ensure audit logs are not automatically deleted (Scored)
#4.1.2	Ensure auditd service is enabled (Scored)
#4.1.3	Ensure auditing for processes that start prior to auditd is enabled (Scored)
#4.1.4	Ensure events that modify date and time information are collected (Scored)
#4.1.5	Ensure events that modify user/group information are collected (Scored)
#4.1.6	Ensure events that modify the system's network environment are collected (Scored)
#4.1.7	Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
#4.1.8	Ensure login and logout events are collected (Scored)
#4.1.9	Ensure session initiation information is collected (Scored)
#4.1.10	Ensure discretionary access control permission modification events are collected (Scored)
#4.1.11	Ensure unsuccessful unauthorized file access attempts are collected (Scored)
#4.1.12	Ensure use of privileged commands is collected (Scored)
#4.1.13	Ensure successful file system mounts are collected (Scored)
#4.1.14	Ensure file deletion events by users are collected (Scored)
#4.1.15	Ensure changes to system administration scope (sudoers) is collected (Scored)
#4.1.16	Ensure system administrator actions (sudolog) are collected (Scored)
#4.1.17	Ensure kernel module loading and unloading is collected (Scored)
#4.1.18	Ensure the audit configuration is immutable (Scored)
#4.2	Configure Logging
#4.2.1	Configure rsyslog
#4.2.1.1	Ensure rsyslog Service is enabled (Scored)
#4.2.1.2	Ensure logging is configured (Not Scored)
#4.2.1.3	Ensure rsyslog default file permissions configured (Scored)
#4.2.1.4	Ensure rsyslog is configured to send logs to a remote log host (Scored)
#4.2.1.5	Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)
#4.2.2	Configure syslog-ng
#4.2.2.1	Ensure syslog-ng service is enabled (Scored)
#4.2.2.2	Ensure logging is configured (Not Scored)
#4.2.2.3	Ensure syslog-ng default file permissions configured (Scored)
#4.2.2.4	Ensure syslog-ng is configured to send logs to a remote log host (Not Scored)
#4.2.2.5	Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored)
#4.2.3	Ensure rsyslog or syslog-ng is installed (Scored)
#4.2.4	Ensure permissions on all logfiles are configured (Scored)
#4.3	Ensure logrotate is configured (Not Scored)
#5	Access, Authentication and Authorization
#5.1	Configure cron
#5.1.1	Ensure cron daemon is enabled (Scored)
#5.1.2	Ensure permissions on /etc/crontab are configured (Scored)
#5.1.3	Ensure permissions on /etc/cron.hourly are configured (Scored)
#5.1.4	Ensure permissions on /etc/cron.daily are configured (Scored)
#5.1.5	Ensure permissions on /etc/cron.weekly are configured (Scored)
#5.1.6	Ensure permissions on /etc/cron.monthly are configured (Scored)
#5.1.7	Ensure permissions on /etc/cron.d are configured (Scored)
#5.1.8	Ensure at/cron is restricted to authorized users (Scored)
#5.2	SSH Server Configuration
#5.2.1	Ensure permissions on /etc/ssh/sshd_config are configured (Scored)
#5.2.2	Ensure SSH Protocol is set to 2 (Scored)
#5.2.3	Ensure SSH LogLevel is set to INFO (Scored)
#5.2.4	Ensure SSH X11 forwarding is disabled (Scored)
#5.2.5	Ensure SSH MaxAuthTries is set to 4 or less (Scored)
#5.2.6	Ensure SSH IgnoreRhosts is enabled (Scored)
#5.2.7	Ensure SSH HostbasedAuthentication is disabled (Scored)
#5.2.8	Ensure SSH root login is disabled (Scored)
#5.2.9	Ensure SSH PermitEmptyPasswords is disabled (Scored)
#5.2.10	Ensure SSH PermitUserEnvironment is disabled (Scored)
#5.2.11	Ensure only approved ciphers are used (Scored)
#5.2.12	Ensure only approved MAC algorithms are used (Scored)
#5.2.13	Ensure SSH Idle Timeout Interval is configured (Scored)
#5.2.14	Ensure SSH LoginGraceTime is set to one minute or less (Scored)
#5.2.15	Ensure SSH access is limited (Scored)
#5.2.16	Ensure SSH warning banner is configured (Scored)
#5.3	Configure PAM
#5.3.1	Ensure password creation requirements are configured (Scored)
#5.3.2	Ensure lockout for failed password attempts is configured (Scored)
#5.3.3	Ensure password reuse is limited (Scored)
#5.3.4	Ensure password hashing algorithm is SHA-512 (Scored)
#5.4	User Accounts and Environment
#5.4.1	Set Shadow Password Suite Parameters
#5.4.1.1	Ensure password expiration is 90 days or less (Scored)
#5.4.1.2	Ensure minimum days between password changes is 7 or more (Scored)
#5.4.1.3	Ensure password expiration warning days is 7 or more (Scored)
#5.4.1.4	Ensure inactive password lock is 30 days or less (Scored)
#5.4.2	Ensure system accounts are non-login (Scored)
#5.4.3	Ensure default group for the root account is GID 0 (Scored)
#5.4.4	Ensure default user umask is 027 or more restrictive (Scored)
#5.5	Ensure root login is restricted to system console (Not Scored)
#5.6	Ensure access to the su command is restricted (Scored)
#6	System Maintenance
#6.1	System File Permissions
#6.1.1	Audit system file permissions (Not Scored)
#6.1.2	Ensure permissions on /etc/passwd are configured (Scored)
#6.1.3	Ensure permissions on /etc/shadow are configured (Scored)
#6.1.4	Ensure permissions on /etc/group are configured (Scored)
#6.1.5	Ensure permissions on /etc/gshadow are configured (Scored)
#6.1.6	Ensure permissions on /etc/passwd- are configured (Scored)
#6.1.7	Ensure permissions on /etc/shadow- are configured (Scored)
#6.1.8	Ensure permissions on /etc/group- are configured (Scored)
#6.1.9	Ensure permissions on /etc/gshadow- are configured (Scored)
#6.1.10	Ensure no world writable files exist (Scored)
#6.1.11	Ensure no unowned files or directories exist (Scored)
#6.1.12	Ensure no ungrouped files or directories exist (Scored)
#6.1.13	Audit SUID executables (Not Scored)
#6.1.14	Audit SGID executables (Not Scored)
echo "6.2	    User and Group Settings"
#6.2.1	Ensure password fields are not empty (Scored)
#6.2.2	Ensure no legacy "+" entries exist in /etc/passwd (Scored)
#6.2.3	Ensure no legacy "+" entries exist in /etc/shadow (Scored)
#6.2.4	Ensure no legacy "+" entries exist in /etc/group (Scored)
#6.2.5	Ensure root is the only UID 0 account (Scored)
#6.2.6	Ensure root PATH Integrity (Scored)
#6.2.7	Ensure all users' home directories exist (Scored)
#6.2.8	Ensure users' home directories permissions are 750 or more restrictive (Scored)
#6.2.9	Ensure users own their home directories (Scored)
#6.2.10	Ensure users' dot files are not group or world writable (Scored)
#6.2.11	Ensure no users have .forward files (Scored)
#6.2.12	Ensure no users have .netrc files (Scored)
#6.2.13	Ensure users' .netrc Files are not group or world accessible (Scored)
#6.2.14	Ensure no users have .rhosts files (Scored)
#6.2.15	Ensure all groups in /etc/passwd exist in /etc/group (Scored)
#6.2.16	Ensure no duplicate UIDs exist (Scored)
#6.2.17	Ensure no duplicate GIDs exist (Scored)
#6.2.18	Ensure no duplicate user names exist (Scored)
#6.2.19	Ensure no duplicate group names exist (Scored)


Este arquivo contém um script de shell para configurar o Red Hat Enterprise Linux 7 em conformidade com o benchmark CIS Red Hat Enterprise Linux 7 v2.1.0. Ele foi testado contra o Red Hat Enterprise Linux 7.2 conforme avaliado pelo CIS-CAT v3.0.26.

Para executar o script, passe um único parâmetro para o perfil desejado:

# sh CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v2.1.0.sh "Nível 1 - Servidor"
# sh CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v2.1.0.sh "Nível 2 - Servidor"
# sh CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v2.1.0.sh "Nível 1 - Estação de trabalho"
# sh CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v2.1.0.sh "Nível 2 - Estação de trabalho"
#Se nenhum parâmetro for passado, o script será padrão para "Nível 1 - Servidor".

Além dos itens avaliados não cis-cat, os seguintes não são configurados por este script:
Esses parâmetros de controle devem ser analisados e cofigurados manualmente

1.1.2 - 1.1.17 O particionamento do sistema deve ser concluído manualmente.

1.4.2 Certifique-se de \ bootloader \ password \ is \ set | As senhas devem ser configuradas manualmente.

1.5.2 Certifique-se de que \ XD / NX \ support \ is \ enabled |O suporte XD / NX é baseado no kernel.

1.6.1.1 - 1.6.1.3 A modificação das configurações do SELinux pode impedir a inicialização do sistema, deve ser concluída manualmente.

1.6.1.6 A investigação e a remediação devem ser concluídas manualmente

1.7.2 Certifique-se de que \ GDM \ login \ banner \ is \ configurado | A configuração GDM deve ser configurada manualmente para evitar a má configuração.

2.2.15 Certifique-se de que \ mail \ transfer \ agent \ is \ configurado \ for \ local-only \ mode | A remediação depende do MTA em uso.

3.3.3 Verifique se o IPv6 está desativado |Só deve ser desabilitado se não for destinado ao seu ambiente

3.4.3 Verifique se \ /etc/hosts.deny \ is \ configurado | A configuração automatizada pode bloquear a administração.

3.6.2 - 3.6.5 A configuração automatizada pode bloquear a administração. 

4.2.1.2 - 4.2.1.5 A configuração do servidor de log deve ser configurada manualmente para evitar a má configuração.

4.2.2.2 - 4.2.2.5 A configuração do servidor de log deve ser configurada manualmente para evitar a má configuração.

5.2.15 Certifique-se de que \ SSH \ access \ is \ limited |A configuração automatizada pode bloquear a administração.

5.3.2 A configuração pam_faillock.so deve ser configurada manualmente para evitar má configuração.

6.1.10 - 6.1.12 As permissões / existência de arquivos / pastas devem ser atualizadas manualmente.

6.2.1 Certifique-se de \ senha \ fields \ are \ not \ empty |As senhas devem ser configuradas manualmente.

6.2.5A conta UID 0 adequada pode ter sido removida, deve ser completada manualmente.

6.2.6 root PATH deve ser definido pelo usuário final.

6.2.7 - 6.2.14 As permissões de arquivo / pasta de usuário / existência devem ser atualizadas manualmente.

6.2.15 Certifique-se de \ all \ groups \ in \ / etc / passwd \ existing \ in \ / etc / group |A modificação da conta ou criação de grupo deve ser completada manualmente.

6.2.16 - 6.2.17 Os IDs duplicados devem ser resolvidos pelo usuário final.

6.2.18 - 6.2.19 Os nomes duplicados devem ser corrigidos pelo usuário final.