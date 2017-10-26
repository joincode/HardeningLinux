#!/bin/bash
 
echo "Verificando arquivos com permissão de SUID BIT.."
 find / -perm -4000 > /root/auditoria/lista.suid
echo -n "Deseja remover o SUID BIT dos arquivos?(S/N):"
read acao
case $acao in
 S|s)
 chmod -Rv -s /
 echo " Permissões de SUID BIT Removidas!"
sleep 3
exit ;;
 N|n)
 exit ;;
 *)
 echo "Opção Inválida!!"
 sleep 3
 exit ;;
 esac