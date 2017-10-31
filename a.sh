#/bin/bash

#HOST=`hostname`
#DATA=`date +"%d%m%Y-%H%M"`
#TESTE Script

LOG='/drives/c/Users/D3LL/Desktop/AUDITORIA/Auditoria.html'
E='<p><input type="Button" style="width:100px; height:30px; border-radius: 10px; font-family: verdana; background-color: #F7C510" value="EXCEPTION">'
F='<p><input type="Button" style="width:100px; height:30px; border-radius: 10px; font-family: verdana; background-color: #C40001;" value="FAIL">'
P='<p><input type="Button" style="width:100px; height:30px; border-radius: 10px; font-family: verdana; background-color: #137624;" value="PASS">'
#criar aquivo de Log para análise de ambiente
touch $LOG
######################################### 
echo "<!DOCTYPE html><html lang="pt-br"><head><title>Benchmark Hardening CIS-2.1.1</title><meta charset="utf-8"></head><body><h1>Benchmark CIS-2.1.1 | Linux</h1><h2>Este relatório está em conformidade com o Benchmark CIS.2.1.1<h2><h3>Os controles auditados são:</h3><div>" >>$LOG
CONTROL="1.1.PING"
ping localhost
if [ "$?" == "0" ]; then
 echo "$P""$CONTROL">> $LOG
else 
 echo "$P""$CONTROL">> $LOG
fi
#==============================
CONTROL="1.2 LOCALHOST"
ping localhost
if [ "$?" == "0" ]; then
 echo "$P""$CONTROL">> $LOG
else 
 echo "$P""$CONTROL">> $LOG
fi
#==============================
CONTROL="1.3.IPCONFIG"
ipconfigd
if [ "$?" == "0" ]; then
 echo "$P" "$CONTROL">> $LOG
else 
 echo "$F" "$CONTROL">> $LOG
fi
#==============================
CONTROL="1.5.HOSTNAME"
hostname
 echo "$E" "$CONTROL">> $LOG
echo "<p>Auditado por: Roberto Lima | MoL-Ps" >> $LOG
echo "</div></body></html>">> $LOG
echo "Auditoria deste sistema foi realizada em" >> $LOG

date >> $LOG 