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
#=================================Inicio da Auditoria==========================
mkdir -p /root/Auditoria/
###############################################################################
#Controle de variáveis de ambiente
HOST=`hostname`
DATA=`date +"%d%m%Y-%H%M"`
LOG='/root/Auditoria/Auditoria-'$HOST'-'$DATA'.csv'
#criar aquivo de Log para análise de ambiente
touch $LOG
#Usarei a variável CONTROL para cada controle auditado no arquivo .csv 
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
echo "2 Servicos"
echo "2.1 Servicos inetd"
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
echo "2.2 Serviços de proposito especial"
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
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.3.1 Certifique-se de que os redirecionamentos ICMP seguros não são aceitos"
sysctl net.ipv4.conf.default.secure_redirects
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.4 Certifique-se de que os pacotes suspeitos estejam registrados"
sysctl net.ipv4.conf.all.log_martians
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.4.1 Certifique-se de que os pacotes suspeitos estejam registrados"
sysctl net.ipv4.conf.default.log_martians
if [ "$?" == "1" ]; then
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
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.2.8 Certifique-se de que TCP SYN Cookies esteja habilitado"
sysctl net.ipv4.tcp_syncookies
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "3.3 IPv6"
CONTROL="3.3.1 Certifique-se de que as propagandas do roteador IPv6 não são aceitas "
sysctl net.ipv6.conf.all.accept_ra
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.3.1.1 Certifique-se de que as propagandas do roteador IPv6 não são aceitas "
sysctl net.ipv6.conf.default.accept_ra
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.3.2 Certifique-se de que os redirecionamentos do IPv6 não são aceitos"
sysctl net.ipv6.conf.all.accept_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.3.2.2 Certifique-se de que os redirecionamentos do IPv6 não são aceitos"
sysctl net.ipv6.conf.default.accept_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.3.3 Certifique-se de que o IPv6 esteja desativado"
modprobe -c | grep ipv6
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "3.4 TCP Wrappers"
CONTROL="3.4.1 Certifique-se de que o TCP Wrappers esteja instalado"
rpm -q tcp_wrappers
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.4.1 Certifique-se de que o TCP Wrappers esteja instalado"
rpm -q tcp_wrappers-libs
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.4.2 Garanta que /etc/hosts.allow esteja configurado"
cat /etc/hosts.allow
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.4.3 Certifique-se de /etc/hosts.deny está configurado"
cat /etc/hosts.deny
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.4.4 Certifique-se de que as permissões em /etc/hosts.allow estão configuradas"
stat /etc/hosts.allow
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.4.5 Certifique-se de que as permissões em /etc/hosts.deny são 644"
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "3.5 Protocolos de rede pouco frequentes"
CONTROL="3.5.1 Certifique-se de que o DCCP esteja desativado"
modprobe -n -v dccp
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.5.2 Certifique-se de que o SCTP esteja desativado"
modprobe -n -v sctp
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.5.3 Certifique-se de que o RDS esteja desativado"
modprobe -n -v rds
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.5.4 Certifique-se de que TIPC esteja desativado"
modprobe -n -v tipc
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "3.6 Configuração do Firewall"
#O Iptables é uma aplicação de Firewall, que garante o mínimo de segurança desejavel, o script abaixo garante a pontuação inicial de acordo com o CIS_Benchmark_2.1.1
#Para utilização durante a auditoria descomente as linhas abaixo, ou insira os códigos abaixo antes de iniciar a auditoria do sistema para que a pontuação seja aceitavel
#==================Script IPTABLES=====================================
#!/bin/bash
# # Flush IPtables rules
#  iptables -F 
# # Ensure default deny firewall policy
#   iptables -P INPUT DROP iptables -P OUTPUT DROP
#   iptables -P FORWARD DROP
# # Ensure loopback traffic is configured
#   iptables -A INPUT -i lo -j ACCEPT
#   iptables -A OUTPUT -o lo -j ACCEPT
#   iptables -A INPUT -s 127.0.0.0/8 -j DROP
# # Ensure outbound and established connections are configured
#   iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
#   iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
#   iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
#   iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
#   iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT 
#   iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT 
# # Open inbound ssh(tcp port 22) connections
#   iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
#==================FIM do Script IPTABLES==============================
##################################################################################
CONTROL="3.6.1 Certifique-se de que o iptables esteja instalado"
rpm -q iptables
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
#Não esquecer de aplicar as polícas mínimas para auditoria
CONTROL="3.6.2 Certifique-se de que a política de firewall de negação predefinida"
iptables -L
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.6.3 Certifique-se de que o tráfego de loopback esteja configurado"
iptables -L INPUT -v -n
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.6.4 Certifique-se de que as conexões de saída e estabelecidas estão configuradas "
iptables -L -v -n
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.6.5 Certifique-se de que existam regras de firewall para todas as portas abertas"
netstat -ln
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.7 Certifique-se de que as interfaces sem fio estão desabilitadas "
iwconfig
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="3.7.1 Certifique-se de que as interfaces sem fio estão desabilitadas "
ip link show up
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "4 Logging and Auditing"
CONTROL="4.1 Configurar a Contabilidade do Sistema (auditd)"
service auditd reload
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "4.1.1 Configurar retenção de dados"
CONTROL="4.1.1.1 Certifique-se de que o tamanho do armazenamento do log de auditoria esteja configurado"
grep max_log_file /etc/audit/auditd.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.1.2 Certifique-se de que o sistema esteja desabilitado quando os logs de auditoria estiverem cheios"
grep space_left_action /etc/audit/auditd.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.1.2.1 Certifique-se de que o sistema esteja desabilitado quando os logs de auditoria estiverem cheios"
grep action_mail_acct /etc/audit/auditd.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.1.2.2 Certifique-se de que o sistema esteja desabilitado quando os logs de auditoria estiverem cheios"
grep admin_space_left_action /etc/audit/auditd.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.1.3 Certifique-se de que os logs de auditoria não sejam excluídos automaticamente"
grep max_log_file_action /etc/audit/auditd.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.2 Certifique-se de que o serviço de auditoria esteja ativado"
service audit status
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.3 Certifique-se de que a auditoria dos processos iniciados antes da auditoria esteja habilitada"
grep "^\s*linux" /boot/grub2/grub.cfg
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.4 Certifique-se de que os eventos que modificam as informações de data e hora são coletados"
grep time-change /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.4.1 Certifique-se de que os eventos que modificam as informações de data e hora são coletados"
grep time-change /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################

CONTROL="4.1.5 Certifique-se de que os eventos que modificam as informações do usuário / grupo são coletados"
grep identity /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.6 Certifique-se de que os eventos que modificam o ambiente de rede do sistema são coletados"
grep system-locale /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.7 Certifique-se de que os eventos que modificam os controles de acesso obrigatórios do sistema são coletados"
grep MAC-policy /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.8 Certifique-se de que os eventos de login e logout sejam coletados"
grep logins /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.9 Certifique-se de que as informações de iniciação da sessão sejam coletadas"
grep session /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.10 Certifique-se de que os eventos de modificação de permissão de controle de acesso discricionário sejam coletados"
grep perm_mod /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.10.1 Certifique-se de que os eventos de modificação de permissão de controle de acesso discricionário sejam coletados"
grep perm_mod /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.11 Certifique-se de que as tentativas de acesso a arquivos não-aprovadas mal sucedidas sejam coletadas"
grep access /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.12 Certifique-se de que o uso de comandos privilegiados seja coletado"
find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }'
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.13 Certifique-se de que as montagens bem sucedidas do sistema de arquivos sejam coletadas"
grep mounts /etc/audit/audit.rules -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.13.1 Certifique-se de que as montagens bem sucedidas do sistema de arquivos sejam coletadas(64)"
grep mounts /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################

CONTROL="4.1.14 Certifique-se de que os eventos de exclusão de arquivos pelos usuários sejam coletados"
grep delete /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.14.1 Certifique-se de que os eventos de exclusão de arquivos pelos usuários sejam coletados"
grep delete /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################

CONTROL="4.1.15 Assegure-se de que as mudanças no escopo de administração do sistema (sudoers) sejam coletadas"
grep scope /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.16 Certifique-se de que as ações do administrador do sistema (sudolog) sejam coletadas"
grep actions /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.17 Certifique-se de que o carregamento e descarregamento do módulo do kernel seja coletado"
grep modules /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.17.1 Certifique-se de que o carregamento e descarregamento do módulo do kernel seja coletado"
grep modules /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.1.18 Certifique-se de que a configuração da auditoria seja imutável"
grep "^\s*[^#]" /etc/audit/audit.rules | tail -1
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "4.2 Configure o registro"
echo "4.2.1 Configurar rsyslog"
CONTROL="4.2.1.1 Certifique-se de que rsyslog Service esteja ativado"
service rsyslog status
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.2.1.2 Certifique-se de que o log está configurado"
ls -l /var/log/
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.2.1.3 Certifique-se de que as permissões de arquivo padrão do rsyslog estão configuradas"
grep ^\$FileCreateMode /etc/rsyslog.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.2.1.4 Certifique-se de que rsyslog esteja configurado para enviar logs para um host de log remoto)"
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.2.1.5 Certifique-se de que as mensagens rsyslog remotas só são aceitas em hosts de log designados."
grep '$ModLoad imtcp.so' /etc/rsyslog.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "4.2.2 Configure syslog-ng"
CONTROL="4.2.2.1 Certifique-se de que o serviço syslog-ng esteja ativado"
service syslog-ng status
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.2.2.2 Certifique-se de que o log está configurado"
ls -l /var/log/
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.2.2.3 Certifique-se de que as permissões de arquivo padrão do syslog-ng foram configuradas"
grep ^options /etc/syslog-ng/syslog-ng.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
CONTROL="4.2.2.4 Certifique-se de que syslog-ng esteja configurado para enviar logs para um host de log remoto"
cat /etc/syslog-ng/syslog-ng.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.2.2.5 Assegure-se de que as mensagens remotas do syslog-ng só são aceitas em hosts de log designados (Não marcados)"
cat /etc/syslog-ng/syslog-ng.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.2.3 Certifique-se de que rsyslog ou syslog-ng esteja instalado"
rpm -q rsyslog
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.2.3.1 Certifique-se de que rsyslog ou syslog-ng esteja instalado"
rpm -q syslog-ng
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.2.4 Certifique-se de que as permissões em todos os arquivos de log estão configuradas"
find /var/log -type f -ls
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.3 Certifique-se de que Logrotate esteja configurado"
cat /etc/logrotate.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="4.3.1 Certifique-se de que Logrotate esteja configurado"
cat /etc/logrotate.d/ *
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "5 Acesso, Autenticação e Autorização"
echo "5.1 Configure o cron"
CONTROL="5.1.1 Certifique-se de que o daemon cron esteja habilitado"
service crond status
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.1.2 Certifique-se de que as permissões em / etc / crontab estejam configuradas"
stat /etc/crontab
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.1.3 Certifique-se de que as permissões em /etc/cron.hourly estão configuradas"
stat /etc/cron.hourly
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.1.4 Certifique-se de que as permissões em /etc/cron.daily estão configuradas"
stat /etc/cron.daily
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.1.5 Certifique-se de que as permissões em /etc/cron.weekly estão configuradas"
stat /etc/cron.weekly
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.1.6 Certifique-se de que as permissões em /etc/cron.monthly estão configuradas"
stat /etc/cron.monthly
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.1.7 Certifique-se de que as permissões em /etc/cron.d estão configuradas"
stat /etc/cron.d
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.1.8 Certifique-se de que / cron esteja restrito a usuários autorizados"
stat /etc/cron.deny
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.1.8.1 Certifique-se de que / cron esteja restrito a usuários autorizados"
stat /etc/at.deny
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.1.8.2 Certifique-se de que / cron esteja restrito a usuários autorizados"
stat /etc/cron.allow
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.1.8.3 Certifique-se de que / cron esteja restrito a usuários autorizados"
stat /etc/at.allow
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2 Configuração do servidor SSH"
service sshd status
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.1 Certifique-se de que as permissões em / etc / ssh / sshd_config estejam configuradas"
stat /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.2 Certifique-se de que o protocolo SSH esteja definido como 2 "
grep "^Protocol" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.3 Certifique-se de que SSH LogLevel esteja configurado para INFO"
grep "^LogLevel" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.4 Certifique-se de que o encaminhamento do SSH X11 esteja desabilitado "
grep "^X11Forwarding" /etc/ssh/sshd_config
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.5 Certifique-se de que SSH MaxAuthTries esteja configurado para 4 ou menos"
grep "^MaxAuthTries" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.6 Certifique-se de que SSH IgnoreRhosts esteja habilitado"
grep "^IgnoreRhosts" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.7 Certifique-se de que SSH HostbasedAuthentication esteja desativado"
grep "^HostbasedAuthentication" /etc/ssh/sshd_config
if [ "$?" == "1" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.8 Certifique-se de que o login do root SSH esteja desativado"
grep "^PermitRootLogin" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.9 Certifique-se de que SSH PermitEmptyPasswords esteja desabilitado"
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.10 Certifique-se de que SSH PermitUserEnvironment esteja desativado"
grep PermitUserEnvironment /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.11 Certifique-se de que somente os algoritmos MAC aprovados sejam usados ​"
grep "Ciphers" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.12 Certifique-se de que SSH Idle Timeout Interval esteja configurado"
grep "MACs" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.13 Certifique-se de que SSH LoginGraceTime esteja configurado para um minuto ou menos"
grep "^ClientAliveInterval" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.13.1 Certifique-se de que SSH LoginGraceTime esteja configurado para um minuto ou menos"
grep "^ClientAliveCountMax" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.14 Certifique-se de que o acesso SSH é limitado "
grep "^LoginGraceTime" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.15 Certifique-se de que o banner de aviso SSH esteja configurado"
grep "^AllowUsers" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.15.1 Certifique-se de que o banner de aviso SSH esteja configurado"
grep "^AllowGroups" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.15.2 Certifique-se de que o banner de aviso SSH esteja configurado"
 grep "^DenyUsers" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.15.3 Certifique-se de que o banner de aviso SSH esteja configurado"
grep "^DenyGroups" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.2.16 Verifique se o banner de aviso SSH está configurado"
grep "^Banner" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "5.3 Configurar PAM"
CONTROL="5.3.1 Certifique-se de que os requisitos de criação de senha estão configurados"
grep pam_pwquality.so /etc/pam.d/password-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.1.1 Certifique-se de que os requisitos de criação de senha estão configurados"
grep pam_pwquality.so /etc/pam.d/system-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.1.2 Certifique-se de que os requisitos de criação de senha estão configurados"
grep ^minlen /etc/security/pwquality.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.1.3 Certifique-se de que os requisitos de criação de senha estão configurados"
grep ^dcredit /etc/security/pwquality.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.1.4 Certifique-se de que os requisitos de criação de senha estão configurados"
grep ^lcredit /etc/security/pwquality.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.1.5 Certifique-se de que os requisitos de criação de senha estão configurados"
grep ^ocredit /etc/security/pwquality.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.1.6 Certifique-se de que os requisitos de criação de senha estão configurados"
grep ^ucredit /etc/security/pwquality.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.2 Certifique-se de que o bloqueio para tentativas de senha com falha esteja configurado"
cat /etc/pam.d/password-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.2.1 Certifique-se de que o bloqueio para tentativas de senha com falha esteja configurado"
cat /etc/pam.d/system-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.3 Certifique-se de que a reutilização de senhas seja limitada"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.3.1 Certifique-se de que a reutilização de senhas seja limitada"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.4 Certifique-se de que o algoritmo de hashing de senha seja SHA-512"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.3.4.1 Certifique-se de que o algoritmo de hashing de senha seja SHA-512"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "5.4 Contas de usuário e ambiente"
echo "5.4.1 Definir os Parâmetros do Suite da Senha de Sombra"
CONTROL="5.4.1.1 Certifique-se de que a expiração da senha é de 90 dias ou menos"
grep PASS_MAX_DAYS /etc/login.defs
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.1.1.1 Certifique-se de que a expiração da senha é de 90 dias ou menos"
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.1.1.2 Certifique-se de que a expiração da senha é de 90 dias ou menos"
#chage --list #<user>
#Necessário verificação por usuário
  echo "$CONTROL,excepition">> $LOG
##################################################################################
CONTROL="5.4.1.2 Certifique-se de que os dias mínimos entre as alterações de senha sejam 7 ou mais"
grep PASS_MIN_DAYS /etc/login.defs
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.1.2.1 Certifique-se de que os dias mínimos entre as alterações de senha sejam 7 ou mais"
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.1.2.2 Certifique-se de que os dias mínimos entre as alterações de senha sejam 7 ou mais"
#chage --list #<user>
#Necessário verificação por usuário
  echo "$CONTROL,exception">> $LOG
##################################################################################
CONTROL="5.4.1.3 Certifique-se de que os dias de aviso de expiração da senha sejam 7 ou mais"
grep PASS_WARN_AGE /etc/login.defs
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.1.3.1 Certifique-se de que os dias de aviso de expiração da senha sejam 7 ou mais"
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.1.3.2 Certifique-se de que os dias de aviso de expiração da senha sejam 7 ou mais"
#chage --list #<user>
#Necessário verificação por usuário
  echo "$CONTROL,exception">> $LOG
##################################################################################
CONTROL="5.4.1.4 Certifique-se de que o bloqueio de senha inativo seja de 30 dias ou menos"
useradd -D | grep INACTIVE
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.1.4.1 Certifique-se de que o bloqueio de senha inativo seja de 30 dias ou menos"
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.1.4.1 Certifique-se de que o bloqueio de senha inativo seja de 30 dias ou menos"
#chage --list #<user>
#Necessário verificação por usuário
  echo "$CONTROL,exception">> $LOG
##################################################################################
CONTROL="5.4.2 Assegure-se de que as contas do sistema não sejam de login"
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}'
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.3 Verifique se o grupo padrão para a conta raiz é GID 0CONTROL="
grep "^root:" /etc/passwd | cut -f4 -d:
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.4 Certifique-se de que o umask de usuário padrão seja 027 ou mais restritivo"
grep "^umask" /etc/bashrc
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.4.4.1 Certifique-se de que o umask de usuário padrão seja 027 ou mais restritivo"
grep "^umask" /etc/profile
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.5 Certifique-se de que o login do root esteja restrito ao console do sistema"
cat /etc/securetty
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.6 Certifique-se de que o acesso ao comando su esteja restrito "
grep pam_wheel.so /etc/pam.d/su
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="5.6.1 Certifique-se de que o acesso ao comando su esteja restrito "
grep wheel /etc/group
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
echo "6 Manutenção do sistema"
echo "6.1 Permissões do arquivo do sistema"
CONTROL="6.1.1 Permissões do arquivo do sistema de auditoria"
rpm -qf /bin/bash
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.1.1 Permissões do arquivo do sistema de auditoria"
rpm -V bash-4.1.2-29.el6.x86_64
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.1.1 Permissões do arquivo do sistema de auditoria"
rpm -V `rpm -qf /etc/passwd`
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.2 Certifique-se de que as permissões no / etc / passwd estão configuradas"
stat /etc/passwd
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.3 Certifique-se de que as permissões em / etc / shadow estão configuradas"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.4 Certifique-se de que as permissões no / etc / group estejam configuradas"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.5 Certifique-se de que as permissões em / etc / shadow estejam configuradas"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.6 Certifique-se de que as permissões no / etc / passwd- estão configuradas"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.7 Certifique-se de que as permissões em / etc / shadow- estão configuradas"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.8 Certifique-se de que as permissões no / etc / group- estejam configuradas"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.9 Certifique-se de que as permissões em / etc / gshadow estão configuradas"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.10 Certifique-se de que não existam arquivos mundiais graváveis ​"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.11 Certifique-se de que não existam arquivos ou diretórios não possuídos"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.12 Certifique-se de que não existem arquivos ou diretórios desagrupados"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.13 Auditoria SUID executáveis ​​"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.1.14 Auditoria SGID executáveis ​​"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2 Configurações de Usuário e Grupo"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.1 Certifique-se de que os campos de senha não estejam vazios"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.2 Certifique-se de que não existam entradas "+" legadas em / etc / passwd"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.3 Certifique-se de que não existam entradas "+" legadas em / etc / shadow"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.4 Certifique-se de que não existam entradas "+" legadas em / etc / group"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.5 Certifique-se de que a raiz seja a única conta UID 0"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.6 Certifique-se de integridade da PATH raiz "
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.7 Certifique-se de que todos os diretórios domésticos de todos os usuários existam"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.8 Assegure-se de que as permissões dos diretórios domésticos dos usuários sejam 750 ou mais restritivas"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.9 Certifique-se de que os usuários possuem seus diretórios domésticos"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.10 Assegure-se de que os arquivos de ponto dos usuários não sejam gravados em grupo ou gravados no mundo"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.11 Certifique-se de que nenhum usuário tenha arquivos .forward"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.12 Certifique-se de que nenhum usuário tenha arquivos .netrc"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.13 Certifique-se de que os arquivos .netrc dos usuários não sejam acessíveis ao grupo ou ao mundo"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.14 Certifique-se de que nenhum usuário tenha arquivos .rhosts"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.15 Certifique-se de que todos os grupos em / etc / passwd existem em / etc / group"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.16 Certifique-se de que não existem UID duplicados"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.17 Certifique-se de que não existam GID duplicados"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.18 Certifique-se de que não existam nomes de usuários duplicados"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.19 Certifique-se de que não existam nomes de grupos duplicados"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
##################################################################################
CONTROL="6.2.20 Certifique-se de que o grupo das sombras esteja vazio"
if [ "$?" == "0" ]; then
  echo "$CONTROL,pass">> $LOG
  else
  echo "$CONTROL,fail">> $LOG
fi
#===============================Audiotiria do Sistema Finalizada==================