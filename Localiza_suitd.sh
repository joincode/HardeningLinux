#!/bin/bash
2 
3 echo "Verificando arquivos com permissão de SUID BIT.."
4 
5 find / -perm -4000 > /root/auditoria/lista.suid
6 
7 echo -n "Deseja remover o SUID BIT dos arquivos?(S/N):"
8 read acao
9 case $acao in
10  S|s)
11  chmod -Rv -s /
12  echo " Permissões de SUID BIT Removidas!"
13  sleep 3
14  exit ;;
15  N|n)
16  exit ;;
17  *)
18  echo "Opção Inválida!!"
19  sleep 3
20  exit ;;
21 esac