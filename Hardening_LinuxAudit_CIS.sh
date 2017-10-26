#/bin/bash
###############################################################################
# Descrição: Script Hardening em Sistemas Operacionais Linux.
#------------------------------------------------------------------------------
# Usabilidade:
# - Efetuar Hardening baseado em normas utilizadas pelo CIS 2.1.1
# - Utilizado no CentOs 6.9 | CentOs 7 | RHEL6 | RHEL 7
# - ./Hardening_LinuxAudit_CIS.sh
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# ID              Date   version
# Roberto.Lima 2017.10.18 0.1  
#------------------------------------------------------------------------------
###############################################################################
#set -x       #Descommentar essa linha para ver em modo debug o script
###############################################################################
#Para efeito de auditoria o requerimento inicial é que a análise seja efetuda em modo root. 
#Verificar se o Script está sendo executado como Root#
if [ "$EUID" -ne 0 ]
  then echo "Favor executar como root"
  exit
fi
echo "Iniciando Script de Auditoria "
###############################################################################
#Controle de variáveis de ambiente
HOST=`hostname`
DATA=`date +"%d%m%Y-%H%M"`
LOG='Auditoria-'$HOST'-'$DATA'.csv'
#criar aquivo de Log para análise de ambiente
touch $LOG
################################################################################
echo "Iniciando Script de Auditoria " >> $LOG
clear
echo "1 Configuração inicial"
echo "1.1 Configuração do Sistema de Arquivos"
echo "1.1.1 Desativar sistemas de arquivos não utilizados"
CONTROL="1.1.1.1 Certifique-se de que a montagem dos sistemas de arquivos do cramfs esteja desabilitada"
modprobe -n -v cramfs
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
 else 
  echo "$CONTROL,fail">> $LOG
fi
#################################################################################
CONTROL="1.1.1.2 Certifique-se de que a montagem do sistema de arquivos freevxfs está desabilitada"
modprobe -n -v freevxfs
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
 else 
  echo "$CONTROL,fail">> $LOG
fi
#################################################################################
CONTROL="1.1.1.3 Certifique-se de que a montagem do sistema de arquivos jffs2 está desabilitada"
modprobe -n -v jffs2 
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.1.4 Certifique-se de que a montagem do sistema de arquivos hfs esteja desativada"
modprobe -n -v hfs
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.1.5 Certifique-se de que a montagem dos sistemas de arquivos hfsplus está desabilitada"
modprobe -n -v hfsplus
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.1.6 Certifique-se de que a montagem dos sistemas de arquivos do squashfs está desativada"
modprobe -n -v squashfs
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.1.7 Certifique-se de que a montagem dos sistemas de arquivos udf está desativada"
modprobe -n -v udf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.1.8 Certifique-se de que a montagem dos sistemas de arquivos FAT está desativada"
modprobe -n -v vfat
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.2 Certifique-se de que a partição separada existe para /tmp"
mount | grep /tmp 
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL= "1.1.3 Certifique-se de que a opção nodev seja definida / partição tmp"
mount | grep /tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.4 Certifique-se de que a opção nosuid seja definida / partição tmp" 
mount | grep /tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.5 Certifique-se de que existe uma partição separada para /var"
mount | grep /var
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.6 Certifique-se de que existe uma partição separada para /var/tmp"
mount | grep /var/tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.7 Certifique-se de que a opção nodev esteja definida na partição /var/tmp"
mount | grep /var/tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.8 Certifique-se de que a opção nosuid seja definida em / var / tmp partição"
mount | grep /var/tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.9 Certifique-se de que a opção noexec esteja definida na partição / var / tmp"
mount | grep /var/tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.10 Verifique se existe uma partição separada para /var/log"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.11 Verifique se existe uma partição separada para / var / log / audit"
mount | grep /var/log
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.12 Certifique-se de que a partição separada existe para / home"
mount | grep /var/log/audit
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="v1.1.13 Certifique-se de que a opção nodev esteja configurada na partição home / home"
mount | grep /home
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="v1.1.14 Certifique-se de que a opção nodev esteja definida na partição / dev / shm"
mount | grep /home
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.15 Certifique-se de que a opção nosuid seja definida / partição / dev / shm"
mount | grep /dev/shm
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.16 Certifique-se de que a opção noexec esteja configurada na partição / dev / shm"
mount | grep /dev/shm
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.17 Certifique-se de que a opção nodev esteja configurada em partições de mídia removíveis"
mount | grep /dev/shm
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.18 Certifique-se de que a opção nosuid seja definida em partições de mídia removível"
mount
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.19 Certifique-se de que a opção noexec esteja configurada em partições de mídia removíveis "
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.20 Certifique-se de que o bit pegajoso esteja configurado em todos os diretórios com classificação mundial"
mount
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.21 Certifique-se de que o bit pegajoso esteja definido em todos os diretórios que podem ser gravados no mundo inteiro"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.1.22 Desativar a montagem automática"
service autofs status
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "1.2 Configurar atualizações de software"
##################################################################################
CONTROL="1.2.1 Certifique-se de que os repositórios do gerenciador de pacotes estão configurados"
yum repolist
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.2.2 Certifique-se de que as chaves GPG estão configuradas "
grep ^gpgcheck /etc/yum.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.2.3 Controle de integridade do sistema de arquivos"
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.2.4 Certifique-se de que a conexão Red Hat Network ou Subscription Manager esteja configurada"
grep identity /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.2.5 Desativar o rhnsd Daemon"
chkconfig --list rhnsd
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "1.3 Certificar integridade FileSystem"
##################################################################################
CONTROL="1.3.1 Certifique-se de que o AIDE esteja instalado"
rpm -q aide
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.3.2 Certifique-se de que a integridade do sistema de arquivos seja regularmente verificada"
crontab -u root -l | grep aide
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "1.4 Configurações de inicialização seguras"
##################################################################################
CONTROL="1.4.1 Assegure-se de que as permissões na configuração do bootloader estão configuradas"
stat -L -c "%a" /etc/grub.conf | egrep ".00"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.4.2 Certifique-se de que a senha do bootloader esteja configurada"
echo "$CONTROL,exception">> $LOG
#if [ "$?" == "0" ]; then
 # echo "$CONTROL,pass">> $LOG
  #else
  #echo "$CONTROL,fail">> $LOG
#fi
##################################################################################
CONTROL="1.4.3 Certifique-se de autenticação necessária para o modo de usuário único"
grep "SINGLE=/sbin/sulogin" /etc/sysconfig/init && grep "PROMPT=no" /etc/sysconfig/init
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.5 Endurecimento adicional do processo"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "1.5 Additional Process Hardening"
##################################################################################
CONTROL="1.5.1 Certifique-se de que os despejos do núcleo estejam restritos"
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.5.2 Certifique-se de que o suporte XD / NX esteja habilitado"
dmesg | grep NX
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.5.3 Certifique-se de que o aleatorizar o layout do espaço de endereço (ASLR) esteja habilitado"
sysctl kernel.randomize_va_space
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.5.4 Certifique-se de que o pré-link esteja desativado "
rpm -q prelink
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "1.6 Controle de acesso obrigatório"
##################################################################################
CONTROL="1.6.1 Configurar o SELinux"
grep "selinux=0\|enforcing=0" /etc/grub.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.6.1.1 Certifique-se de que o SELinux não está desativado na configuração do carregador de inicialização"
grep "SELINUX=enforcing" /etc/selinux/config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.6.1.2 Certifique-se de que o estado SELinux está a aplicar"
grep SELINUX=enforcing /etc/selinux/config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.6.1.3 Verifique se a política SELinux está configurada"
grep SELINUXTYPE=targeted /etc/selinux/config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.6.1.4 Certifique-se de que não existem damsons não confinados"
rpm -q setroubleshoot
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.6.1.5 Certifique-se de que o Serviço de Tradução MCS (mcstrans) não está instalado"
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.6.1.6 Certifique-se de que não existem damsons não confinados"
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.6.2 Verificar se o SELInux esta instalado"
rpm -q libselinux
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "1.7 Banners de aviso"
echo "v1.7.1 Banners de advertência de linha de comando"
#################################################################################
CONTROL="1.7.1.1 Certifique-se de que a mensagem do dia esteja configurada corretamente"
cat /etc/motd
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.7.1.2 Verifique se o banner de aviso de login local está configurado corretamente"
cat /etc/issue
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.7.1.3 Certifique-se de que o banner de aviso de login remoto esteja configurado corretamente"
cat /etc/issue.net
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="v1.7.1.4 Certifique-se de que as permissões em / etc / motd estão configuradas "
stat /etc/motd
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.7.1.5 Certifique-se de que as permissões no / etc / issue estejam configuradas"
stat /etc/issue
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.7.1.6 Certifique-se de que as permissões no /etc/issue.net estão configuradas "
stat /etc/issue.net
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="1.7.2 Certifique-se de que o banner de login do GDM esteja configurado"
echo "$CONTROL,exception">> $LOG
##################################################################################
CONTROL="1.8 Certifique-se de que as atualizações os patches e o software de segurança adicional estão instalados"
yum check-update
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "2 Serviços"
echo "2.1 Serviços inetd"
#Para efeito de auditoria, os serviços devem ser verificados de acordo com o ambiente proposto
#Listaremos os Serviços em outro log para filtro de necessidade do ambiente.
chkconfig --list >> AuditoriaServicos.csv
CONTROL="2.1.1 Certifique-se de que os serviços de carga não estejam habilitados"
echo "$CONTROL,exception">> $LOG
CONTROL="2.1.2 Certifique-se de que os serviços diurnos não estão ativados"
echo "$CONTROL,exception">> $LOG
CONTROL="2.1.3 Certifique-se de que os serviços de descarte não estão habilitados"
echo "$CONTROL,exception">> $LOG
CONTROL="2.1.4 Certifique-se de que os serviços de eco não estejam habilitados"
echo "$CONTROL,exception">> $LOG
CONTROL="2.1.5 Certifique-se de que os serviços de tempo não estão ativados"
echo "$CONTROL,exception">> $LOG
CONTROL="2.1.6 Certifique-se de que o servidor rsh não esteja habilitado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.1.7 Certifique-se de que o servidor de conversação não esteja ativado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.1.8 Certifique-se de que o servidor telnet não está habilitado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.1.9 Certifique-se de que o servidor tftp não esteja ativado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.1.10 Certifique-se de que o xinetd não está habilitado"
echo "$CONTROL,exception">> $LOG
##################################################################################
echo "2.2 Serviços de propósito especial"
echo "2.2.1 Sincronização de tempo"
CONTROL="2.2.1.1 Certifique-se de que a sincronização de tempo esteja em uso"
rpm -q ntp
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="2.2.1.2 Certifique-se de que ntp esteja configurado"
grep "^restrict" /etc/ntp.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="2.2.1.2.1 Certifique-se de que ntp servidor esteja configurado"
grep "^server" /etc/ntp.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="2.2.1.2.2 Certifique-se de que as OPÇÕES ntp esteja configurado"
grep "^OPTIONS" /etc/sysconfig/ntpd
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="2.2.1.3 Certifique-se de que o chrony esteja configurado"
echo "$CONTROL,exception">> $LOG
##################################################################################
CONTROL="2.2.2 Certifique-se de que X Window System não esteja instalado"
rpm -qa xorg-x11*
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="2.2.3 Certifique-se de que o Servidor Avahi não esteja habilitado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.4 Certifique-se de que CUPS não esteja habilitado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.5 Certifique-se de que o Servidor DHCP não esteja habilitado "
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.6 Certifique-se de que o servidor LDAP não esteja habilitado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.7 Certifique-se de que NFS e RPC não estão habilitados"
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.8 Certifique-se de que o Servidor DNS não está habilitado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.9 Certifique-se de que o Servidor FTP não está ativado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.10 Certifique-se de que o servidor HTTP não está habilitado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.11 Certifique-se de que o servidor IMAP e POP3 não está habilitado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.12 Certifique-se de que o Samba não está habilitado"
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.13 Certifique-se de que o servidor proxy HTTP não esteja ativado "
echo "$CONTROL,exception">> $LOG
CONTROL="2.2.14 Certifique-se de que o Servidor SNMP não está habilitado"
echo "$CONTROL,exception">> $LOG
##################################################################################
CONTROL="2.2.15 Certifique-se de que o agente de transferência de correio esteja configurado para o modo somente local"
netstat -an | grep LIST | grep ":25[[:space:]]"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="2.2.16 Certifique-se de que o serviço rsync não esteja ativado"
echo "$CONTROL,exception">> $LOG
##################################################################################
CONTROL="2.2.17 Certifique-se de que o NIS Server não está habilitado"
echo "$CONTROL,exception">> $LOG
##################################################################################
echo "2.3 Clientes de serviço"
CONTROL="2.3.1 Garantir que o NIS Client não esteja instalado"
rpm -q ypbind
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="2.3.2 Certifique-se de que o cliente rsh não esteja instalado"
rpm -q rsh
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="2.3.3 Certifique-se de que o cliente de conversação não esteja instalado"
rpm -q talk
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="2.3.4 Certifique-se de que o cliente telnet não está instalado"
rpm -q telnet
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="2.3.5 Certifique-se de que o cliente LDAP não esteja instalado"
rpm -q openldap-clients
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "3 Configuração de rede"
echo "3.1 Parâmetros de rede (apenas host)"
CONTROL="3.1.1 Certifique-se de que o reenvio de IP esteja desabilitado "
sysctl net.ipv4.ip_forward
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.1.2 Certifique-se de que o envio do redirecionamento de pacotes esteja desativado"
sysctl net.ipv4.conf.all.send_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "3.2 Parâmetros de Rede (Host e Roteador)"
CONTROL="3.2.1 Certifique-se de que os pacotes roteados de origem não são aceitos"
sysctl net.ipv4.conf.all.accept_source_route
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.1.1 Certifique-se de que os pacotes roteados de origem não são aceitos"
sysctl net.ipv4.conf.default.send_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.2 Certifique-se de que os redirecionamentos ICMP não são aceitos"
sysctl net.ipv4.conf.all.accept_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.2.1 Certifique-se de que os redirecionamentos ICMP não são aceitos"
sysctl net.ipv4.conf.default.accept_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.3 Certifique-se de que os redirecionamentos ICMP seguros não são aceitos"
sysctl net.ipv4.conf.all.secure_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.3.1 Certifique-se de que os redirecionamentos ICMP seguros não são aceitos"
sysctl net.ipv4.conf.default.secure_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.4 Certifique-se de que os pacotes suspeitos estejam registrados"
sysctl net.ipv4.conf.all.log_martians
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.4.1 Certifique-se de que os pacotes suspeitos estejam registrados"
sysctl net.ipv4.conf.default.log_martians
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.5 Certifique-se de que os pedidos de ICMP de transmissão são ignorados"
sysctl net.ipv4.icmp_echo_ignore_broadcasts
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.6 Certifique-se de que as respostas ICMP falsas sejam ignoradas"
sysctl net.ipv4.icmp_ignore_bogus_error_responses
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.7 Certifique-se de que o Filtro do caminho reverso está ativado "
sysctl net.ipv4.conf.all.rp_filter
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.7.1 Certifique-se de que o Filtro do caminho reverso está ativado "
sysctl net.ipv4.conf.default.rp_filter
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.8 Certifique-se de que TCP SYN Cookies esteja habilitado"
sysctl net.ipv4.tcp_syncookies
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "3.3 IPv6"
CONTROL="3.3.1 Certifique-se de que as propagandas do roteador IPv6 não são aceitas "
CONTROL="3.3.2 Certifique-se de que os redirecionamentos do IPv6 não são aceitos"
CONTROL="3.3.3 Certifique-se de que o IPv6 esteja desativado"
CONTROL="3.4 TCP Wrappers"
CONTROL="3.4.1 Certifique-se de que o TCP Wrappers esteja instalado"
CONTROL="3.4.2 Garanta que /etc/hosts.allow esteja configurado"
CONTROL="3.4.3 Certifique-se de /etc/hosts.deny está configurado"
CONTROL="3.4.4 Certifique-se de que as permissões em /etc/hosts.allow estão configuradas"
CONTROL="3.4.5 Certifique-se de que as permissões em /etc/hosts.deny são 644"
CONTROL="3.5 Protocolos de rede pouco frequentes"
CONTROL="3.5.1 Certifique-se de que o DCCP esteja desativado"
CONTROL="3.5.2 Certifique-se de que o SCTP esteja desativado"
CONTROL="3.5.3 Certifique-se de que o RDS esteja desativado"
CONTROL="3.5.4 Certifique-se de que TIPC esteja desativado"
CONTROL="3.6 Configuração do Firewall"
CONTROL="3.6.1 Certifique-se de que o iptables esteja instalado"
CONTROL="3.6.2 Certifique-se de que a política de firewall de negação predefinida"
CONTROL="3.6.3 Certifique-se de que o tráfego de loopback esteja configurado"
CONTROL="3.6.4 Certifique-se de que as conexões de saída e estabelecidas estão configuradas "
CONTROL="3.6.5 Certifique-se de que existam regras de firewall para todas as portas abertas"
CONTROL="3.7 Certifique-se de que as interfaces sem fio estão desabilitadas "
echo "4 Logging and Auditing"
CONTROL="4.1 Configurar a Contabilidade do Sistema (auditd)"
CONTROL="4.1.1 Configurar retenção de dados"
CONTROL="4.1.1.1 Certifique-se de que o tamanho do armazenamento do log de auditoria esteja configurado"
CONTROL="4.1.1.2 Certifique-se de que o sistema esteja desabilitado quando os logs de auditoria estiverem cheios"
CONTROL="4.1.1.3 Certifique-se de que os logs de auditoria não sejam excluídos automaticamente"
CONTROL="4.1.2 Certifique-se de que o serviço de auditoria esteja ativado"
CONTROL="4.1.3 Certifique-se de que a auditoria dos processos iniciados antes da auditoria esteja habilitada"
CONTROL="4.1.4 Certifique-se de que os eventos que modificam as informações de data e hora são coletados"
CONTROL="4.1.5 Certifique-se de que os eventos que modificam as informações do usuário / grupo são coletados"
CONTROL="4.1.6 Certifique-se de que os eventos que modificam o ambiente de rede do sistema são coletados"
CONTROL="4.1.7 Certifique-se de que os eventos que modificam os controles de acesso obrigatórios do sistema são coletados"
CONTROL="4.1.8 Certifique-se de que os eventos de login e logout sejam coletados"
CONTROL="4.1.9 Certifique-se de que as informações de iniciação da sessão sejam coletadas"
CONTROL="4.1.10 Certifique-se de que os eventos de modificação de permissão de controle de acesso discricionário sejam coletados"
CONTROL="4.1.11 Certifique-se de que as tentativas de acesso a arquivos não-aprovadas mal sucedidas sejam coletadas"
CONTROL="4.1.12 Certifique-se de que o uso de comandos privilegiados seja coletado"
CONTROL="4.1.13 Certifique-se de que as montagens bem sucedidas do sistema de arquivos sejam coletadas"
CONTROL="4.1.14 Certifique-se de que os eventos de exclusão de arquivos pelos usuários sejam coletados"
CONTROL="4.1.15 Assegure-se de que as mudanças no escopo de administração do sistema (sudoers) sejam coletadas"
CONTROL="4.1.16 Certifique-se de que as ações do administrador do sistema (sudolog) sejam coletadas"
CONTROL="4.1.17 Certifique-se de que o carregamento e descarregamento do módulo do kernel seja coletado"
CONTROL="4.1.18 Certifique-se de que a configuração da auditoria seja imutável"
CONTROL="4.2 Configure o registro"
CONTROL="4.2.1 Configurar rsyslog"
CONTROL="4.2.1.1 Certifique-se de que rsyslog Service esteja ativado"
CONTROL="4.2.1.2 Certifique-se de que o log está configurado"
CONTROL="4.2.1.3 Certifique-se de que as permissões de arquivo padrão do rsyslog estão configuradas"
CONTROL="4.2.1.4 Certifique-se de que rsyslog esteja configurado para enviar logs para um host de log remoto)"
CONTROL="4.2.1.5 Certifique-se de que as mensagens rsyslog remotas só são aceitas em hosts de log designados."
CONTROL="4.2.2 Configure syslog-ng"
CONTROL="4.2.2.1 Certifique-se de que o serviço syslog-ng esteja ativado"
CONTROL="4.2.2.2 Certifique-se de que o log está configurado"
CONTROL="4.2.2.3 Certifique-se de que as permissões de arquivo padrão do syslog-ng foram configuradas"
CONTROL="4.2.2.4 Certifique-se de que syslog-ng esteja configurado para enviar logs para um host de log remoto"
CONTROL="4.2.2.5 Assegure-se de que as mensagens remotas do syslog-ng só são aceitas em hosts de log designados (Não marcados)"
CONTROL="4.2.3 Certifique-se de que rsyslog ou syslog-ng esteja instalado"
CONTROL="4.2.4 Certifique-se de que as permissões em todos os arquivos de log estão configuradas"
CONTROL="4.3 Certifique-se de que Logrotate esteja configurado"
echo "5 Acesso, Autenticação e Autorização"
CONTROL="5.1 Configure o cron"
CONTROL="5.1.1 Certifique-se de que o daemon cron esteja habilitado"
CONTROL="5.1.2 Certifique-se de que as permissões em / etc / crontab estejam configuradas"
CONTROL="5.1.3 Certifique-se de que as permissões em /etc/cron.hourly estão configuradas"
CONTROL="5.1.4 Certifique-se de que as permissões em /etc/cron.daily estão configuradas"
CONTROL="5.1.5 Certifique-se de que as permissões em /etc/cron.weekly estão configuradas"
CONTROL="5.1.6 Certifique-se de que as permissões em /etc/cron.monthly estão configuradas"
CONTROL="5.1.7 Certifique-se de que as permissões em /etc/cron.d estão configuradas"
CONTROL="5.1.8 Certifique-se de que / cron esteja restrito a usuários autorizados"
CONTROL="5.2 Configuração do servidor SSH"
CONTROL="5.2.1 Certifique-se de que as permissões em / etc / ssh / sshd_config estejam configuradas"
CONTROL="5.2.2 Certifique-se de que o protocolo SSH esteja definido como 2 "
CONTROL="5.2.3 Certifique-se de que SSH LogLevel esteja configurado para INFO"
CONTROL="5.2.4 Certifique-se de que o encaminhamento do SSH X11 esteja desabilitado "
CONTROL="5.2.5 Certifique-se de que SSH MaxAuthTries esteja configurado para 4 ou menos"
CONTROL="5.2.6 Certifique-se de que SSH IgnoreRhosts esteja habilitado"
CONTROL="5.2.7 Certifique-se de que SSH HostbasedAuthentication esteja desativado"
CONTROL="5.2.8 Certifique-se de que o login do root SSH esteja desativado"
CONTROL="5.2.9 Certifique-se de que SSH PermitEmptyPasswords esteja desabilitado"
CONTROL="5.2.10 Certifique-se de que SSH PermitUserEnvironment esteja desativado"
CONTROL="5.2.11 Certifique-se de que somente os algoritmos MAC aprovados sejam usados ​"
CONTROL="5.2.12 Certifique-se de que SSH Idle Timeout Interval esteja configurado"
CONTROL="5.2.13 Certifique-se de que SSH LoginGraceTime esteja configurado para um minuto ou menos"
CONTROL="5.2.14 Certifique-se de que o acesso SSH é limitado "
CONTROL="5.2.15 Certifique-se de que o banner de aviso SSH esteja configurado"
CONTROL="5.3 Configurar PAM"
CONTROL="5.3.1 Certifique-se de que os requisitos de criação de senha estão configurados"
CONTROL="5.3.2 Certifique-se de que o bloqueio para tentativas de senha com falha esteja configurado"
CONTROL="5.3.3 Certifique-se de que a reutilização de senhas seja limitada"
CONTROL="5.3.4 Certifique-se de que o algoritmo de hashing de senha seja SHA-512"
CONTROL="5.4 Contas de usuário e ambiente"
CONTROL="5.4.1 Definir os Parâmetros do Suite da Senha de Sombra"
CONTROL="5.4.1.1 Certifique-se de que a expiração da senha é de 90 dias ou menos"
CONTROL="5.4.1.2 Certifique-se de que os dias mínimos entre as alterações de senha sejam 7 ou mais"
CONTROL="5.4.1.3 Certifique-se de que os dias de aviso de expiração da senha sejam 7 ou mais"
CONTROL="5.4.1.4 Certifique-se de que o bloqueio de senha inativo seja de 30 dias ou menos"
CONTROL="5.4.2 Assegure-se de que as contas do sistema não sejam de login"
CONTROL="5.4.3 Verifique se o grupo padrão para a conta raiz é GID 0CONTROL="
CONTROL="5.4.4 Certifique-se de que o umask de usuário padrão seja 027 ou mais restritivo"
CONTROL="5.5 Certifique-se de que o login do root esteja restrito ao console do sistema"
CONTROL="5.6 Certifique-se de que o acesso ao comando su esteja restrito "
echo "6 Manutenção do sistema"
CONTROL="6.1 Permissões do arquivo do sistema"
CONTROL="6.1.1 Permissões do arquivo do sistema de auditoria"
CONTROL="6.1.2 Certifique-se de que as permissões no / etc / passwd estão configuradas"
CONTROL="6.1.3 Certifique-se de que as permissões em / etc / shadow estão configuradas"
CONTROL="6.1.4 Certifique-se de que as permissões no / etc / group estejam configuradas"
CONTROL="6.1.5 Certifique-se de que as permissões em / etc / shadow estejam configuradas"
CONTROL="6.1.6 Certifique-se de que as permissões no / etc / passwd- estão configuradas"
CONTROL="6.1.7 Certifique-se de que as permissões em / etc / shadow- estão configuradas"
CONTROL="6.1.8 Certifique-se de que as permissões no / etc / group- estejam configuradas"
CONTROL="6.1.9 Certifique-se de que as permissões em / etc / gshadow estão configuradas"
CONTROL="6.1.10 Certifique-se de que não existam arquivos mundiais graváveis ​"
CONTROL="6.1.11 Certifique-se de que não existam arquivos ou diretórios não possuídos"
CONTROL="6.1.12 Certifique-se de que não existem arquivos ou diretórios desagrupados"
CONTROL="6.1.13 Auditoria SUID executáveis ​​"
CONTROL="6.1.14 Auditoria SGID executáveis ​​"
CONTROL="6.2 Configurações de Usuário e Grupo"
CONTROL="6.2.1 Certifique-se de que os campos de senha não estejam vazios"
CONTROL="6.2.2 Certifique-se de que não existam entradas "+" legadas em / etc / passwd"
CONTROL="6.2.3 Certifique-se de que não existam entradas "+" legadas em / etc / shadow"
CONTROL="6.2.4 Certifique-se de que não existam entradas "+" legadas em / etc / group"
CONTROL="6.2.5 Certifique-se de que a raiz seja a única conta UID 0"
CONTROL="6.2.6 Certifique-se de integridade da PATH raiz "
CONTROL="6.2.7 Certifique-se de que todos os diretórios domésticos de todos os usuários existam"
CONTROL="6.2.8 Assegure-se de que as permissões dos diretórios domésticos dos usuários sejam 750 ou mais restritivas"
CONTROL="6.2.9 Certifique-se de que os usuários possuem seus diretórios domésticos"
CONTROL="6.2.10 Assegure-se de que os arquivos de ponto dos usuários não sejam gravados em grupo ou gravados no mundo"
CONTROL="6.2.11 Certifique-se de que nenhum usuário tenha arquivos .forward"
CONTROL="6.2.12 Certifique-se de que nenhum usuário tenha arquivos .netrc"
CONTROL="6.2.13 Certifique-se de que os arquivos .netrc dos usuários não sejam acessíveis ao grupo ou ao mundo"
CONTROL="6.2.14 Certifique-se de que nenhum usuário tenha arquivos .rhosts"
CONTROL="6.2.15 Certifique-se de que todos os grupos em / etc / passwd existem em / etc / group"
CONTROL="6.2.16 Certifique-se de que não existem UID duplicados"
CONTROL="6.2.17 Certifique-se de que não existam GID duplicados"
CONTROL="6.2.18 Certifique-se de que não existam nomes de usuários duplicados"
CONTROL="6.2.19 Certifique-se de que não existam nomes de grupos duplicados"
CONTROL="6.2.20 Certifique-se de que o grupo das sombras esteja vazio"