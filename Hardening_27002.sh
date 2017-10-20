#!/bin/bash
###############################################################################
# Descrição: Script para Hardening Linux 
#------------------------------------------------------------------------------
# Usabilidade:
# - Hardening em Sistema Operacional Linux de acordo com a Norma ISO 27002 
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# ID            Date          version
# Roberto.Lima 2017.10.19     0.1
#------------------------------------------------------------------------------
###############################################################################
#Há dois modos de Hardening em sistemas Linux, sendo um em Sistema Operacional e outro em Kernel
#em modo root criamos a pasta auditoria e deixaremos direcionamos os Logs para o arquivo auditoria.txt

    dpkg -l | awk '{print $2,$3}' | sed '1,5d' > /root/auditoria/auditoria.txt

#dpkg filtramos |awk  segunda e terceira coluna ($2,$3) pois são os nomes dos programas e versões| Sed remove as 5 primeitas linhas e lança dentro de /root/auditoria.
#Analisaremos o log
    nano  /root/auditoria/auditoria.txt
# editor de texto de sua preferencia |vi | vim| nano | pico
# exemplo para remocao de pacotes, é o wget

    aptitude purge wget
# norma ABNT NBR ISO/IEC 27002:2005, no item 11.6.1
#Permissão Suid Bid
 mount /cdrom
 cp /cdrom/bs7799/localiza_suid.sh /root/auditoria
 vim /root/auditoria/localiza_suid.sh

#1.4. Arquivos com permissão de Suid Bit
#Por recomendação da norma ABNT NBR ISO/IEC 27002:2005, no item 11.6.1
#1.4.2. Execução do Procedimento
#script localiza_suid.sh:
 mount /cdrom
 cp /cdrom/bs7799/localiza_suid.sh /root/auditoria
 vim /root/auditoria/localiza_suid.sh

#2 – Como vai ser a primeira vez que vamos executa-lo, não vamos remover as
#permissões de Suid Bit. Vamos primeiro gerar a lista e analisar:
 cd /root/auditoria
 chmod +x localiza_suid.sh
 ./localiza_suid.sh

#3 – Agora podemos analisar a lista e ver quais binários possuem a permissão de SuidBit:
  vim lista.suid
Nesse momento, devemos pensar onde devamos manter a permissão, 

#4 – No nosso ambiente, vamos retirar todas as permissões de Suid Bit, e aplicar somente naqueles que realmente são necessários:
 ./localiza_suid.sh
 chmod +s /bin/su
 chmod +s /usr/bin/passwd

#1.5.1. Conformidade com a norma
#A norma ABNT NBR ISO/IEC 27002:2005 diz no item 10.4.1, que convém que sejam

#1 – Remontem a partição com a opção noexec e tente executar uma das shells que foram copiadas para o /tmp. Esse teste pode ser feito inclusive com o usuário root:
 mount -o remount,rw,noexec /tmp
 monunt
 cd /tmp
 ./sh

#Saida do comando tem de ser algo do tipo “permissão negada”.
#2 – Agora que ficou claro o uso dos recursos de montagem, definam as respectivas
#políticas para o filesystem proposto, considerando a tabela a seguir:
#Ponto de Montagem Nosuid Noexec
/ - -
/home X X
/usr - -
/tmp X X
/var X X
/var/log X X
#Tabela 1.5.2. – Estrutura de partições
#Se queremos usar o comando passwd com Suid Bit, nós não podemos aplicar no nosuid aos /usr, pois o comando se encontra em /usr/bin.
#3 – Exemplo de como está tabela de ficar no /etc/fstab:
 vim /etc/fstab
#1 /dev/sda1 / ext3 defaults 0 1
#2 /dev/sda2 none swap sw 0 0
#3 /dev/sda5 /home ext3 defaults,nosuid,noexec 0 1
#4 /dev/sda7 /tmp ext3 defaults,nosuid,noexec 0 1
#5 /dev/sda8 /var ext3 defaults,nosuid,noexec 0 1
#6 /dev/sda9 /var/log ext3 defaults,nosuid,noexec 0 1
-----------------------------------------------------------------------------------------------------
