#!/bin/bash
###############################################################################
# Descricao: Script Hardening em Sistemas Operacionais Linux.
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
#Para efeito de auditoria o requerimento inicial e que a analise seja efetuda em modo root. 
#Verificar se o Script esta sendo executado como Root#
if [ "$EUID" -ne 0 ]
  then echo "Favor executar como root"
  exit
fi
#=================================Inicio da Auditoria==========================
mkdir -p /root/Auditoria/
###############################################################################
#Controle de variaveis de ambiente
#HOST=`hostname`
#DATA=`date +"%d/%m/%Y-%H:%M"`
#LOG='/root/Auditoria/Auditoria-'$HOST'-'$DATA'.csv'
LOG='/root/Auditoria/Auditoria.html'
E='<p style="margin: 0.25em 0"><input type="Button" style="width:100px; height:30px; border-radius: 10px; font-family: verdana; background-color: #F7C510;" value="EXCEPTION">'
F='<p style="margin: 0.25em 0"><input type="Button" style="width:100px; height:30px; border-radius: 10px; font-family: verdana; background-color: #C40001;" value="FAIL">'
P='<p style="margin: 0.25em 0"><input type="Button" style="width:100px; height:30px; border-radius: 10px; font-family: verdana; background-color: #137624;" value="PASS">'
LOGSERVICE='/root/Auditoria/AuditoriaServicos.csv'
#criar aquivo de Log para analise de ambiente
touch $LOG
#Usarei a variavel CONTROL para cada controle auditado no arquivo .csv 
################################################################################
echo "<!DOCTYPE html><html lang="pt-br"><head><title>Benchmark Hardening CIS-2.1.1</title><meta charset="utf-8"></head><body><h1>Benchmark CIS-2.1.1 | Linux</h1><h2>Este relatório está em conformidade com o Benchmark CIS.2.1.1</h2><h3>Os controles auditados são:</h3><div>" >>$LOG
#echo "1 Configuracao inicial">> $LOG
#echo "1.1 Configuracao do Sistema de Arquivos">> $LOG
#echo "1.1.1 Desativar sistemas de arquivos nao utilizados">> $LOG
echo ""
CONTROL="1.1.1.1 Certifique-se de que a montagem de arquivos do cramfs esteja desabilitada"
modprobe -n -v cramfs
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
 else 
  echo "$CONTROL" "$F">> $LOG
fi
#################################################################################
CONTROL="1.1.1.2 Certifique-se de que a montagem do sistema de arquivos freevxfs esta desabilitada"
modprobe -n -v freevxfs
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
 else 
  echo "$CONTROL" "$F">> $LOG
fi
#################################################################################
CONTROL="1.1.1.3 Certifique-se de que a montagem do sistema de arquivos jffs2 esta desabilitada"
modprobe -n -v jffs2 
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.1.4 Certifique-se de que a montagem do sistema de arquivos hfs esteja desativada"
modprobe -n -v hfs
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.1.5 Certifique-se de que a montagem dos sistemas de arquivos hfsplus esta desabilitada"
modprobe -n -v hfsplus
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.1.6 Certifique-se de que a montagem dos sistemas de arquivos do squashfs esta desativada"
modprobe -n -v squashfs
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.1.7 Certifique-se de que a montagem dos sistemas de arquivos udf esta desativada"
modprobe -n -v udf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.1.8 Certifique-se de que a montagem dos sistemas de arquivos FAT esta desativada"
modprobe -n -v vfat
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.2 Certifique-se de que a particao separada existe para /tmp"
mount | grep /tmp 
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.3 Certifique-se de que a opcao nodev seja definida / particao tmp"
mount | grep /tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.4 Certifique-se de que a opcao nosuid seja definida / particao tmp" 
mount | grep /tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.5 Certifique-se de que existe uma particao separada para /var"
mount | grep /var
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.6 Certifique-se de que existe uma particao separada para /var/tmp"
mount | grep /var/tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.7 Certifique-se de que a opcao nodev esteja definida na particao /var/tmp"
mount | grep /var/tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.8 Certifique-se de que a opcao nosuid seja definida em / var / tmp particao"
mount | grep /var/tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.9 Certifique-se de que a opcao noexec esteja definida na particao / var / tmp"
mount | grep /var/tmp
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.10 Verifique se existe uma particao separada para /var/log"
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.11 Verifique se existe uma particao separada para / var / log / audit"
mount | grep /var/log
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.12 Certifique-se de que a particao separada existe para / home"
mount | grep /var/log/audit
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="v1.1.13 Certifique-se de que a opcao nodev esteja configurada na particao home / home"
mount | grep /home
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="v1.1.14 Certifique-se de que a opcao nodev esteja definida na particao / dev / shm"
mount | grep /home
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.15 Certifique-se de que a opcao nosuid seja definida / particao / dev / shm"
mount | grep /dev/shm
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.16 Certifique-se de que a opcao noexec esteja configurada na particao / dev / shm"
mount | grep /dev/shm
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.17 Certifique-se de que a opcao nodev esteja configurada em particoes de midia removiveis"
mount | grep /dev/shm
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.18 Certifique-se de que a opcao nosuid seja definida em particoes de midia removivel"
mount
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.19 Certifique-se de que a opcao noexec esteja configurada em particoes de midia removiveis "
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.20 Certifique-se de que o bit pegajoso esteja configurado em todos os diretorios com classificacao mundial"
mount
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.21 Certifique-se de que o bit pegajoso esteja definido em todos os diretorios que podem ser gravados no mundo inteiro"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.1.22 Desativar a montagem automatica"
service autofs status
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "1.2 Configurar atualizacoes de software"
CONTROL="1.2.1 Certifique-se de que os repositorios do gerenciador de pacotes estao configurados"
yum repolist
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.2.2 Certifique-se de que as chaves GPG estao configuradas "
grep ^gpgcheck /etc/yum.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.2.3 Controle de integridade do sistema de arquivos"
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.2.4 Certifique-se de que a conexao Red Hat Network ou Subscription Manager esteja configurada"
grep identity /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.2.5 Desativar o rhnsd Daemon"
chkconfig --list rhnsd
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "1.3 Certificar integridade FileSystem"
CONTROL="1.3.1 Certifique-se de que o AIDE esteja instalado"
rpm -q aide
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.3.2 Certifique-se de que a integridade do sistema de arquivos seja regularmente verificada"
crontab -u root -l | grep aide
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "1.4 Configuracoes de inicializacao seguras"
CONTROL="1.4.1 Assegure-se de que as permissoes na configuracao do bootloader estao configuradas"
stat -L -c "%a" /etc/grub.conf | egrep ".00"
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.4.2 Certifique-se de que a senha do bootloader esteja configurada"
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="1.4.3 Certifique-se de autenticacao necessaria para o modo de usuario único"
grep "SINGLE=/sbin/sulogin" /etc/sysconfig/init && grep "PROMPT=no" /etc/sysconfig/init
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.5 Endurecimento adicional do processo"
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "1.5 Additional Process Hardening"
##################################################################################
CONTROL="1.5.1 Certifique-se de que os despejos do núcleo estejam restritos"
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.5.2 Certifique-se de que o suporte XD / NX esteja habilitado"
dmesg | grep NX
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.5.3 Certifique-se de que o aleatorizar o layout do espaco de endereco (ASLR) esteja habilitado"
sysctl kernel.randomize_va_space
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.5.4 Certifique-se de que o pre-link esteja desativado "
rpm -q prelink
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "1.6 Controle de acesso obrigatorio"
CONTROL="1.6.1 Configurar o SELinux"
grep "selinux=0\|enforcing=0" /etc/grub.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.6.1.1 Certifique-se de que o SELinux nao esta desativado na configuracao do carregador de inicializacao"
grep "SELINUX=enforcing" /etc/selinux/config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.6.1.2 Certifique-se de que o estado SELinux esta a aplicar"
grep SELINUX=enforcing /etc/selinux/config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.6.1.3 Verifique se a politica SELinux esta configurada"
grep SELINUXTYPE=targeted /etc/selinux/config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.6.1.4 Certifique-se de que nao existem damsons nao confinados"
rpm -q setroubleshoot
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.6.1.5 Certifique-se de que o Servico de Traducao MCS (mcstrans) nao esta instalado"
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.6.1.6 Certifique-se de que nao existem damsons nao confinados"
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.6.2 Verificar se o SELInux esta instalado"
rpm -q libselinux
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "1.7 Banners de aviso"
echo "v1.7.1 Banners de advertencia de linha de comando"
#################################################################################
CONTROL="1.7.1.1 Certifique-se de que a mensagem do dia esteja configurada corretamente"
cat /etc/motd
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.7.1.2 Verifique se o banner de aviso de login local esta configurado corretamente"
cat /etc/issue
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.7.1.3 Certifique-se de que o banner de aviso de login remoto esteja configurado corretamente"
cat /etc/issue.net
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="v1.7.1.4 Certifique-se de que as permissoes em / etc / motd estao configuradas "
stat /etc/motd
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.7.1.5 Certifique-se de que as permissoes no / etc / issue estejam configuradas"
stat /etc/issue
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.7.1.6 Certifique-se de que as permissoes no /etc/issue.net estao configuradas "
stat /etc/issue.net
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="1.7.2 Certifique-se de que o banner de login do GDM esteja configurado"
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="1.8 Certifique-se de que as atualizacoes os patches e o software de seguranca adicional estao instalados"
yum check-update
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "2 Servicos"
echo "2.1 Servicos inetd"
#Para efeito de auditoria, os servicos devem ser verificados de acordo com o ambiente proposto
#Listaremos os Servicos em outro log para filtro de necessidade do ambiente.
chkconfig --list >> $LOGSERVICE
CONTROL="2.1.1 Certifique-se de que os servicos de carga nao estejam habilitados"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.1.2 Certifique-se de que os servicos diurnos nao estao ativados"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.1.3 Certifique-se de que os servicos de descarte nao estao habilitados"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.1.4 Certifique-se de que os servicos de eco nao estejam habilitados"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.1.5 Certifique-se de que os servicos de tempo nao estao ativados"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.1.6 Certifique-se de que o servidor rsh nao esteja habilitado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.1.7 Certifique-se de que o servidor de conversacao nao esteja ativado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.1.8 Certifique-se de que o servidor telnet nao esta habilitado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.1.9 Certifique-se de que o servidor tftp nao esteja ativado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.1.10 Certifique-se de que o xinetd nao esta habilitado"
echo "$CONTROL" "$E">> $LOG
##################################################################################
echo "2.2 Servicos de proposito especial"
echo "2.2.1 Sincronizacao de tempo"
CONTROL="2.2.1.1 Certifique-se de que a sincronizacao de tempo esteja em uso"
rpm -q ntp
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="2.2.1.2 Certifique-se de que ntp esteja configurado"
grep "^restrict" /etc/ntp.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="2.2.1.2.1 Certifique-se de que ntp servidor esteja configurado"
grep "^server" /etc/ntp.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="2.2.1.2.2 Certifique-se de que as OPcoes ntp esteja configurado"
grep "^OPTIONS" /etc/sysconfig/ntpd
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="2.2.1.3 Certifique-se de que o chrony esteja configurado"
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="2.2.2 Certifique-se de que X Window System nao esteja instalado"
rpm -qa xorg-x11*
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="2.2.3 Certifique-se de que o Servidor Avahi nao esteja habilitado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.4 Certifique-se de que CUPS nao esteja habilitado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.5 Certifique-se de que o Servidor DHCP nao esteja habilitado "
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.6 Certifique-se de que o servidor LDAP nao esteja habilitado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.7 Certifique-se de que NFS e RPC nao estao habilitados"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.8 Certifique-se de que o Servidor DNS nao esta habilitado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.9 Certifique-se de que o Servidor FTP nao esta ativado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.10 Certifique-se de que o servidor HTTP nao esta habilitado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.11 Certifique-se de que o servidor IMAP e POP3 nao esta habilitado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.12 Certifique-se de que o Samba nao esta habilitado"
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.13 Certifique-se de que o servidor proxy HTTP nao esteja ativado "
echo "$CONTROL" "$E">> $LOG
CONTROL="2.2.14 Certifique-se de que o Servidor SNMP nao esta habilitado"
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="2.2.15 Certifique-se de que o agente de transferencia de correio esteja configurado para o modo somente local"
netstat -an | grep LIST | grep ":25[[:space:]]"
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="2.2.16 Certifique-se de que o servico rsync nao esteja ativado"
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="2.2.17 Certifique-se de que o NIS Server nao esta habilitado"
echo "$CONTROL" "$E">> $LOG
##################################################################################
echo "2.3 Clientes de servico"
CONTROL="2.3.1 Garantir que o NIS Client nao esteja instalado"
rpm -q ypbind
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="2.3.2 Certifique-se de que o cliente rsh nao esteja instalado"
rpm -q rsh
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="2.3.3 Certifique-se de que o cliente de conversacao nao esteja instalado"
rpm -q talk
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="2.3.4 Certifique-se de que o cliente telnet nao esta instalado"
rpm -q telnet
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="2.3.5 Certifique-se de que o cliente LDAP nao esteja instalado"
rpm -q openldap-clients
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "3 Configuracao de rede"
echo "3.1 Parametros de rede (apenas host)"
CONTROL="3.1.1 Certifique-se de que o reenvio de IP esteja desabilitado "
sysctl net.ipv4.ip_forward
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.1.2 Certifique-se de que o envio do redirecionamento de pacotes esteja desativado"
sysctl net.ipv4.conf.all.send_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "3.2 Parametros de Rede (Host e Roteador)"
CONTROL="3.2.1 Certifique-se de que os pacotes roteados de origem nao sao aceitos"
sysctl net.ipv4.conf.all.accept_source_route
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.1.1 Certifique-se de que os pacotes roteados de origem nao sao aceitos"
sysctl net.ipv4.conf.default.send_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.2 Certifique-se de que os redirecionamentos ICMP nao sao aceitos"
sysctl net.ipv4.conf.all.accept_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.2.1 Certifique-se de que os redirecionamentos ICMP nao sao aceitos"
sysctl net.ipv4.conf.default.accept_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.3 Certifique-se de que os redirecionamentos ICMP seguros nao sao aceitos"
sysctl net.ipv4.conf.all.secure_redirects
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.3.1 Certifique-se de que os redirecionamentos ICMP seguros nao sao aceitos"
sysctl net.ipv4.conf.default.secure_redirects
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.4 Certifique-se de que os pacotes suspeitos estejam registrados"
sysctl net.ipv4.conf.all.log_martians
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.4.1 Certifique-se de que os pacotes suspeitos estejam registrados"
sysctl net.ipv4.conf.default.log_martians
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.5 Certifique-se de que os pedidos de ICMP de transmissao sao ignorados"
sysctl net.ipv4.icmp_echo_ignore_broadcasts
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.6 Certifique-se de que as respostas ICMP falsas sejam ignoradas"
sysctl net.ipv4.icmp_ignore_bogus_error_responses
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.7 Certifique-se de que o Filtro do caminho reverso esta ativado "
sysctl net.ipv4.conf.all.rp_filter
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.7.1 Certifique-se de que o Filtro do caminho reverso esta ativado "
sysctl net.ipv4.conf.default.rp_filter
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.2.8 Certifique-se de que TCP SYN Cookies esteja habilitado"
sysctl net.ipv4.tcp_syncookies
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "3.3 IPv6"
CONTROL="3.3.1 Certifique-se de que as propagandas do roteador IPv6 nao sao aceitas "
sysctl net.ipv6.conf.all.accept_ra
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.3.1.1 Certifique-se de que as propagandas do roteador IPv6 nao sao aceitas "
sysctl net.ipv6.conf.default.accept_ra
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.3.2 Certifique-se de que os redirecionamentos do IPv6 nao sao aceitos"
sysctl net.ipv6.conf.all.accept_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.3.2.2 Certifique-se de que os redirecionamentos do IPv6 nao sao aceitos"
sysctl net.ipv6.conf.default.accept_redirects
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.3.3 Certifique-se de que o IPv6 esteja desativado"
modprobe -c | grep ipv6
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "3.4 TCP Wrappers"
CONTROL="3.4.1 Certifique-se de que o TCP Wrappers esteja instalado"
rpm -q tcp_wrappers
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.4.1 Certifique-se de que o TCP Wrappers esteja instalado"
rpm -q tcp_wrappers-libs
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.4.2 Garanta que /etc/hosts.allow esteja configurado"
cat /etc/hosts.allow
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.4.3 Certifique-se de /etc/hosts.deny esta configurado"
cat /etc/hosts.deny
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.4.4 Certifique-se de que as permissoes em /etc/hosts.allow estao configuradas"
stat /etc/hosts.allow
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.4.5 Certifique-se de que as permissoes em /etc/hosts.deny sao 644"
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "3.5 Protocolos de rede pouco frequentes"
CONTROL="3.5.1 Certifique-se de que o DCCP esteja desativado"
modprobe -n -v dccp
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.5.2 Certifique-se de que o SCTP esteja desativado"
modprobe -n -v sctp
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.5.3 Certifique-se de que o RDS esteja desativado"
modprobe -n -v rds
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.5.4 Certifique-se de que TIPC esteja desativado"
modprobe -n -v tipc
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "3.6 Configuracao do Firewall"
#O Iptables e uma aplicacao de Firewall, que garante o minimo de seguranca desejavel, o script abaixo garante a pontuacao inicial de acordo com o CIS_Benchmark_2.1.1
#Para utilizacao durante a auditoria descomente as linhas abaixo, ou insira os codigos abaixo antes de iniciar a auditoria do sistema para que a pontuacao seja aceitavel
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
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
#nao esquecer de aplicar as policas minimas para auditoria
CONTROL="3.6.2 Certifique-se de que a politica de firewall de negacao predefinida"
iptables -L
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.6.3 Certifique-se de que o trafego de loopback esteja configurado"
iptables -L INPUT -v -n
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.6.4 Certifique-se de que as conexoes de saida e estabelecidas estao configuradas "
iptables -L -v -n
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.6.5 Certifique-se de que existam regras de firewall para todas as portas abertas"
netstat -ln
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.7 Certifique-se de que as interfaces sem fio estao desabilitadas "
iwconfig
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="3.7.1 Certifique-se de que as interfaces sem fio estao desabilitadas "
ip link show up
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "4 Logging and Auditing"
CONTROL="4.1 Configurar a Contabilidade do Sistema (auditd)"
service auditd reload
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "4.1.1 Configurar retencao de dados"
CONTROL="4.1.1.1 Certifique-se de que o tamanho do armazenamento do log de auditoria esteja configurado"
grep max_log_file /etc/audit/auditd.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.1.2 Certifique-se de que o sistema esteja desabilitado quando os logs de auditoria estiverem cheios"
grep space_left_action /etc/audit/auditd.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.1.2.1 Certifique-se de que o sistema esteja desabilitado quando os logs de auditoria estiverem cheios"
grep action_mail_acct /etc/audit/auditd.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.1.2.2 Certifique-se de que o sistema esteja desabilitado quando os logs de auditoria estiverem cheios"
grep admin_space_left_action /etc/audit/auditd.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.1.3 Certifique-se de que os logs de auditoria nao sejam excluidos automaticamente"
grep max_log_file_action /etc/audit/auditd.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.2 Certifique-se de que o servico de auditoria esteja ativado"
service audit status
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.3 Certifique-se de que a auditoria dos processos iniciados antes da auditoria esteja habilitada"
grep "^\s*linux" /boot/grub2/grub.cfg
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.4 Certifique-se de que os eventos que modificam as informacoes de data e hora sao coletados"
grep time-change /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.4.1 Certifique-se de que os eventos que modificam as informacoes de data e hora sao coletados"
grep time-change /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################

CONTROL="4.1.5 Certifique-se de que os eventos que modificam as informacoes do usuario / grupo sao coletados"
grep identity /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.6 Certifique-se de que os eventos que modificam o ambiente de rede do sistema sao coletados"
grep system-locale /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.7 Certifique-se de que os eventos que modificam os controles de acesso obrigatorios do sistema sao coletados"
grep MAC-policy /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.8 Certifique-se de que os eventos de login e logout sejam coletados"
grep logins /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.9 Certifique-se de que as informacoes de iniciacao da sessao sejam coletadas"
grep session /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.10 Certifique-se de que os eventos de modificacao de permissao de controle de acesso discricionario sejam coletados"
grep perm_mod /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.10.1 Certifique-se de que os eventos de modificacao de permissao de controle de acesso discricionario sejam coletados"
grep perm_mod /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.11 Certifique-se de que as tentativas de acesso a arquivos nao-aprovadas mal sucedidas sejam coletadas"
grep access /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.12 Certifique-se de que o uso de comandos privilegiados seja coletado"
find /dev/sda -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }'
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.13 Certifique-se de que as montagens bem sucedidas do sistema de arquivos sejam coletadas"
grep mounts /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.13.1 Certifique-se de que as montagens bem sucedidas do sistema de arquivos sejam coletadas(64)"
grep mounts /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################

CONTROL="4.1.14 Certifique-se de que os eventos de exclusao de arquivos pelos usuarios sejam coletados"
grep delete /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.14.1 Certifique-se de que os eventos de exclusao de arquivos pelos usuarios sejam coletados"
grep delete /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################

CONTROL="4.1.15 Assegure-se de que as mudancas no escopo de administracao do sistema (sudoers) sejam coletadas"
grep scope /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.16 Certifique-se de que as acoes do administrador do sistema (sudolog) sejam coletadas"
grep actions /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.17 Certifique-se de que o carregamento e descarregamento do modulo do kernel seja coletado"
grep modules /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.17.1 Certifique-se de que o carregamento e descarregamento do modulo do kernel seja coletado"
grep modules /etc/audit/audit.rules
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.1.18 Certifique-se de que a configuracao da auditoria seja imutavel"
grep "^\s*[^#]" /etc/audit/audit.rules | tail -1
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "4.2 Configure o registro"
echo "4.2.1 Configurar rsyslog"
CONTROL="4.2.1.1 Certifique-se de que rsyslog Service esteja ativado"
service rsyslog status
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.2.1.2 Certifique-se de que o log esta configurado"
ls -l /var/log/
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.2.1.3 Certifique-se de que as permissoes de arquivo padrao do rsyslog estao configuradas"
grep ^\$FileCreateMode /etc/rsyslog.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.2.1.4 Certifique-se de que rsyslog esteja configurado para enviar logs para um host de log remoto)"
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.2.1.5 Certifique-se de que as mensagens rsyslog remotas so sao aceitas em hosts de log designados."
grep '$ModLoad imtcp.so' /etc/rsyslog.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "4.2.2 Configure syslog-ng"
CONTROL="4.2.2.1 Certifique-se de que o servico syslog-ng esteja ativado"
service syslog-ng status
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.2.2.2 Certifique-se de que o log esta configurado"
ls -l /var/log/
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.2.2.3 Certifique-se de que as permissoes de arquivo padrao do syslog-ng foram configuradas"
grep ^options /etc/syslog-ng/syslog-ng.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
CONTROL="4.2.2.4 Certifique-se de que syslog-ng esteja configurado para enviar logs para um host de log remoto"
cat /etc/syslog-ng/syslog-ng.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.2.2.5 Assegure-se de que as mensagens remotas do syslog-ng so sao aceitas em hosts de log designados (nao marcados)"
cat /etc/syslog-ng/syslog-ng.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.2.3 Certifique-se de que rsyslog ou syslog-ng esteja instalado"
rpm -q rsyslog
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.2.3.1 Certifique-se de que rsyslog ou syslog-ng esteja instalado"
rpm -q syslog-ng
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.2.4 Certifique-se de que as permissoes em todos os arquivos de log estao configuradas"
find /var/log -type f -ls
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.3 Certifique-se de que Logrotate esteja configurado"
cat /etc/logrotate.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="4.3.1 Certifique-se de que Logrotate esteja configurado"
cat /etc/logrotate.d/ *
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "5 Acesso, Autenticacao e Autorizacao"
echo "5.1 Configure o cron"
CONTROL="5.1.1 Certifique-se de que o daemon cron esteja habilitado"
service crond status
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.1.2 Certifique-se de que as permissoes em / etc / crontab estejam configuradas"
stat /etc/crontab
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.1.3 Certifique-se de que as permissoes em /etc/cron.hourly estao configuradas"
stat /etc/cron.hourly
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.1.4 Certifique-se de que as permissoes em /etc/cron.daily estao configuradas"
stat /etc/cron.daily
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.1.5 Certifique-se de que as permissoes em /etc/cron.weekly estao configuradas"
stat /etc/cron.weekly
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.1.6 Certifique-se de que as permissoes em /etc/cron.monthly estao configuradas"
stat /etc/cron.monthly
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.1.7 Certifique-se de que as permissoes em /etc/cron.d estao configuradas"
stat /etc/cron.d
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.1.8 Certifique-se de que / cron esteja restrito a usuarios autorizados"
stat /etc/cron.deny
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.1.8.1 Certifique-se de que / cron esteja restrito a usuarios autorizados"
stat /etc/at.deny
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.1.8.2 Certifique-se de que / cron esteja restrito a usuarios autorizados"
stat /etc/cron.allow
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.1.8.3 Certifique-se de que / cron esteja restrito a usuarios autorizados"
stat /etc/at.allow
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2 Configuracao do servidor SSH"
service sshd status
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.1 Certifique-se de que as permissoes em / etc / ssh / sshd_config estejam configuradas"
stat /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.2 Certifique-se de que o protocolo SSH esteja definido como 2 "
grep "^Protocol" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.3 Certifique-se de que SSH LogLevel esteja configurado para INFO"
grep "^LogLevel" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.4 Certifique-se de que o encaminhamento do SSH X11 esteja desabilitado "
grep "^X11Forwarding" /etc/ssh/sshd_config
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.5 Certifique-se de que SSH MaxAuthTries esteja configurado para 4 ou menos"
grep "^MaxAuthTries" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.6 Certifique-se de que SSH IgnoreRhosts esteja habilitado"
grep "^IgnoreRhosts" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.7 Certifique-se de que SSH HostbasedAuthentication esteja desativado"
grep "^HostbasedAuthentication" /etc/ssh/sshd_config
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.8 Certifique-se de que o login do root SSH esteja desativado"
grep "^PermitRootLogin" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.9 Certifique-se de que SSH PermitEmptyPasswords esteja desabilitado"
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.10 Certifique-se de que SSH PermitUserEnvironment esteja desativado"
grep PermitUserEnvironment /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.11 Certifique-se de que somente os algoritmos MAC aprovados sejam usados ​"
grep "Ciphers" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.12 Certifique-se de que SSH Idle Timeout Interval esteja configurado"
grep "MACs" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.13 Certifique-se de que SSH LoginGraceTime esteja configurado para um minuto ou menos"
grep "^ClientAliveInterval" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.13.1 Certifique-se de que SSH LoginGraceTime esteja configurado para um minuto ou menos"
grep "^ClientAliveCountMax" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.14 Certifique-se de que o acesso SSH e limitado "
grep "^LoginGraceTime" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.15 Certifique-se de que o banner de aviso SSH esteja configurado"
grep "^AllowUsers" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.15.1 Certifique-se de que o banner de aviso SSH esteja configurado"
grep "^AllowGroups" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.15.2 Certifique-se de que o banner de aviso SSH esteja configurado"
 grep "^DenyUsers" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.15.3 Certifique-se de que o banner de aviso SSH esteja configurado"
grep "^DenyGroups" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.2.16 Verifique se o banner de aviso SSH esta configurado"
grep "^Banner" /etc/ssh/sshd_config
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "5.3 Configurar PAM"
CONTROL="5.3.1 Certifique-se de que os requisitos de criacao de senha estao configurados"
grep pam_pwquality.so /etc/pam.d/password-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.1.1 Certifique-se de que os requisitos de criacao de senha estao configurados"
grep pam_pwquality.so /etc/pam.d/system-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.1.2 Certifique-se de que os requisitos de criacao de senha estao configurados"
grep ^minlen /etc/security/pwquality.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.1.3 Certifique-se de que os requisitos de criacao de senha estao configurados"
grep ^dcredit /etc/security/pwquality.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.1.4 Certifique-se de que os requisitos de criacao de senha estao configurados"
grep ^lcredit /etc/security/pwquality.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.1.5 Certifique-se de que os requisitos de criacao de senha estao configurados"
grep ^ocredit /etc/security/pwquality.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.1.6 Certifique-se de que os requisitos de criacao de senha estao configurados"
grep ^ucredit /etc/security/pwquality.conf
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.2 Certifique-se de que o bloqueio para tentativas de senha com falha esteja configurado"
cat /etc/pam.d/password-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.2.1 Certifique-se de que o bloqueio para tentativas de senha com falha esteja configurado"
cat /etc/pam.d/system-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.3 Certifique-se de que a reutilizacao de senhas seja limitada"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.3.1 Certifique-se de que a reutilizacao de senhas seja limitada"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.4 Certifique-se de que o algoritmo de hashing de senha seja SHA-512"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.3.4.1 Certifique-se de que o algoritmo de hashing de senha seja SHA-512"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "5.4 Contas de usuario e ambiente"
echo "5.4.1 Definir os Parametros do Suite da Senha de Sombra"
CONTROL="5.4.1.1 Certifique-se de que a expiracao da senha e de 90 dias ou menos"
grep PASS_MAX_DAYS /etc/login.defs
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.1.1.1 Certifique-se de que a expiracao da senha e de 90 dias ou menos"
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.1.1.2 Certifique-se de que a expiracao da senha e de 90 dias ou menos"
#chage --list #<user>
#Necessario verificacao por usuario
  echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="5.4.1.2 Certifique-se de que os dias minimos entre as alteracoes de senha sejam 7 ou mais"
grep PASS_MIN_DAYS /etc/login.defs
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.1.2.1 Certifique-se de que os dias minimos entre as alteracoes de senha sejam 7 ou mais"
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.1.2.2 Certifique-se de que os dias minimos entre as alteracoes de senha sejam 7 ou mais"
#chage --list #<user>
#Necessario verificacao por usuario
  echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="5.4.1.3 Certifique-se de que os dias de aviso de expiracao da senha sejam 7 ou mais"
grep PASS_WARN_AGE /etc/login.defs
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.1.3.1 Certifique-se de que os dias de aviso de expiracao da senha sejam 7 ou mais"
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.1.3.2 Certifique-se de que os dias de aviso de expiracao da senha sejam 7 ou mais"
#chage --list #<user>
#Necessario verificacao por usuario
  echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="5.4.1.4 Certifique-se de que o bloqueio de senha inativo seja de 30 dias ou menos"
useradd -D | grep INACTIVE
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.1.4.1 Certifique-se de que o bloqueio de senha inativo seja de 30 dias ou menos"
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.1.4.1 Certifique-se de que o bloqueio de senha inativo seja de 30 dias ou menos"
#chage --list #<user>
#Necessario verificacao por usuario
  echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="5.4.2 Assegure-se de que as contas do sistema nao sejam de login"
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}'
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.3 Verifique se o grupo padrao para a conta raiz e GID 0CONTROL="
grep "^root:" /etc/passwd | cut -f4 -d:
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.4 Certifique-se de que o umask de usuario padrao seja 027 ou mais restritivo"
grep "^umask" /etc/bashrc
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.4.4.1 Certifique-se de que o umask de usuario padrao seja 027 ou mais restritivo"
grep "^umask" /etc/profile
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.5 Certifique-se de que o login do root esteja restrito ao console do sistema"
cat /etc/securetty
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.6 Certifique-se de que o acesso ao comando su esteja restrito "
grep pam_wheel.so /etc/pam.d/su
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="5.6.1 Certifique-se de que o acesso ao comando su esteja restrito "
grep wheel /etc/group
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "6 Manutencao do sistema"
echo "6.1 Permissoes do arquivo do sistema"
CONTROL="6.1.1 Permissoes do arquivo do sistema de auditoria"
rpm -qf /bin/bash
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.1.1 Permissoes do arquivo do sistema de auditoria"
rpm -V bash-4.1.2-29.el6.x86_64
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.1.2 Permissoes do arquivo do sistema de auditoria RHEL7 |CentOS 7"
rpm -V bash-4.1.2-29.el7.x86_64
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.1.3 Permissoes do arquivo do sistema de auditoria"
rpm -V `rpm -qf /etc/passwd`
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.1.4 Permissoes do arquivo do sistema de auditoria"
rpm -Va --nomtime --nosize --nomd5 --nolinkto > /root/Auditoria/Auditoria-$CONTROL.csv
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################

CONTROL="6.1.2 Certifique-se de que as permissoes no / etc / passwd estao configuradas"
stat /etc/passwd
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.3 Certifique-se de que as permissoes em / etc / shadow estao configuradas"
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.4 Certifique-se de que as permissoes no / etc / group estejam configuradas"
stat /etc/group
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.5 Certifique-se de que as permissoes em / etc / shadow estejam configuradas"
stat /etc/gshadow
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.6 Certifique-se de que as permissoes no / etc / passwd- estao configuradas"
stat /etc/passwd-
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.7 Certifique-se de que as permissoes em / etc / shadow- estao configuradas"
stat /etc/shadow-
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.8 Certifique-se de que as permissoes no / etc / group- estejam configuradas"
stat /etc/group-
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.9 Certifique-se de que as permissoes em / etc / gshadow estao configuradas"
stat /etc/gshadow-
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.10 Certifique-se de que nao existam arquivos mundiais gravaveis ​"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.11 Certifique-se de que nao existam arquivos ou diretorios nao possuidos"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.12 Certifique-se de que nao existem arquivos ou diretorios desagrupados"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.13 Auditoria SUID executaveis ​​"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.1.14 Auditoria SGID executaveis ​​"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
echo "6.2 Configuracoes de Usuario e Grupo"
CONTROL="6.2.1 Certifique-se de que os campos de senha nao estejam vazios"
cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.2.2 Certifique-se de que nao existam entradas "+" legadas em / etc / passwd"
grep '^+:' /etc/passwd
if [ "$?" == "1" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.2.3 Certifique-se de que nao existam entradas "+" legadas em / etc / shadow"
grep '^+:' /etc/shadow
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.2.4 Certifique-se de que nao existam entradas "+" legadas em / etc / group"
grep '^+:' /etc/group
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi
##################################################################################
CONTROL="6.2.5 Certifique-se de que a raiz seja a única conta UID 0"
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'
if [ "$?" == "0" ]; then
  echo "$CONTROL" "$P">> $LOG
  else
  echo "$CONTROL" "$F">> $LOG
fi

##################################################################################
#executarscrit controle 6.2.6
CONTROL="6.2.6 Certifique-se de integridade da PATH raiz "
#!/bin/bash 
#for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
#  dirperm=`ls -ld $dir | cut -f1 -d" "` 
#  if [ `echo $dirperm | cut -c6 ` != "-" ]; then
#    echo "Group Write permission set on directory $dir" 
#  fi 
#  if [ `echo $dirperm | cut -c8 ` != "-" ]; then 
#    echo "Other Read permission set on directory $dir" 
#  fi 
#  if [ `echo $dirperm | cut -c9 ` != "-" ]; then
#    echo "Other Write permission set on directory $dir" 
#  fi
#  if [ `echo $dirperm | cut -c10 ` != "-" ]; then
#    echo "Other Execute permission set on directory $dir" 
#  fi 
#done
#  if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.7 Certifique-se de que todos os diretorios domesticos de todos os usuarios existam"
#!/bin/bash
#cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
#  if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
#    echo "The home directory ($dir) of user $user does not exist." 
#  fi 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.8 Assegure-se de que as permissoes dos diretorios domesticos dos usuarios sejam 750 ou mais restritivas"
#!/bin/bash 
#for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
#  dirperm=`ls -ld $dir | cut -f1 -d" "` 
#  if [ `echo $dirperm | cut -c6 ` != "-" ]; then
#    echo "Group Write permission set on directory $dir" 
#  fi 
#  if [ `echo $dirperm | cut -c8 ` != "-" ]; then 
#    echo "Other Read permission set on directory $dir" 
#  fi 
#  if [ `echo $dirperm | cut -c9 ` != "-" ]; then
#    echo "Other Write permission set on directory $dir" 
#  fi
#  if [ `echo $dirperm | cut -c10 ` != "-" ]; then
#    echo "Other Execute permission set on directory $dir" 
#  fi 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.9 Certifique-se de que os usuarios possuem seus diretorios domesticos"
#!/bin/bash 
#cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
#  if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then
#  owner=$(stat -L -c "%U" "$dir") 
#    if [ "$owner" != "$user" ]; then
#    echo "The home directory ($dir) of user $user is owned by $owner." 
#    fi 
#  fi 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.10 Assegure-se de que os arquivos de ponto dos usuarios nao sejam gravados em grupo ou gravados no mundo"
#!/bin/bash
#for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
#  for file in $dir/.[A-Za-z0-9]*; do
#    if [ ! -h "$file" -a -f "$file" ]; then
#      fileperm=`ls -ld $file | cut -f1 -d" "` 
#      if [ `echo $fileperm | cut -c6 ` != "-" ]; then
#       echo "Group Write permission set on file $file" 
#      fi 
#      if [ `echo $fileperm | cut -c9 ` != "-" ]; then
#       echo "Other Write permission set on file $file" 
#      fi 
#    fi 
#  done 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.11 Certifique-se de que nenhum usuario tenha arquivos .forward"
#!/bin/bash 
#for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
#  if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
#    echo ".forward file $dir/.forward exists" 
#  fi 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.12 Certifique-se de que nenhum usuario tenha arquivos .netrc"
#!/bin/bash 
#for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
#  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#    echo ".netrc file $dir/.netrc exists" 
#  fi 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi

##################################################################################
CONTROL="6.2.13 Certifique-se de que os arquivos .netrc dos usuarios nao sejam acessiveis ao grupo ou ao mundo"
#!/bin/bash 
#for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
#  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#    echo ".netrc file $dir/.netrc exists" 
#  fi 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.14 Certifique-se de que nenhum usuario tenha arquivos .rhosts"
#!/bin/bash 
#for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
#  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#    echo ".netrc file $dir/.netrc exists" 
#  fi 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.15 Certifique-se de que todos os grupos em / etc / passwd existem em / etc / group"
#!/bin/bash 
#for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
#  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#    echo ".netrc file $dir/.netrc exists" 
#  fi 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.16 Certifique-se de que nao existem UID duplicados"
#!/bin/bash 
#for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
#  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#    echo ".netrc file $dir/.netrc exists" 
#  fi 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.17 Certifique-se de que nao existam GID duplicados"
#!/bin/bash 
#for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
#  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#    echo ".netrc file $dir/.netrc exists" 
#  fi 
#done
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.18 Certifique-se de que nao existam nomes de usuarios duplicados"
#!/bin/bash 
#for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
#  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#    echo ".netrc file $dir/.netrc exists" 
#  fi 
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
##################################################################################
CONTROL="6.2.19 Certifique-se de que nao existam nomes de grupos duplicados"
#!/bin/bash 
#for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
#  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#    echo ".netrc file $dir/.netrc exists" 
#  fi 
#if [ "$?" == "0" ]; then
#  echo "$CONTROL" "$P">> $LOG
#  else
#  echo "$CONTROL" "$F">> $LOG
#fi
echo "$CONTROL" "$E">> $LOG
echo "<p>Auditado por: Roberto Lima | MoL-Ps </p>" >> $LOG
echo "</div></body></html>" >> $LOG
#echo "Auditoria deste sistema foi realizada em" >> $LOG

date +%d/%m/%Y-%H:%M >> $LOG 
#===============================Audiotiria do Sistema Finalizada==================