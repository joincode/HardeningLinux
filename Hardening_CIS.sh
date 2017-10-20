#/bin/bash
###############################################################################
# Descrição: Script Hardening em Sistemas Operacionais Linux.
#------------------------------------------------------------------------------
# Usabilidade:
# - Efetuar Hardening baseado em normas utilizadas pelo CIS 
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# ID              Date   version
# Roberto.Lima 2017.10.18 0.1  
#------------------------------------------------------------------------------
###############################################################################

SLEEP1='sleep 3'
SLEEP2='sleep 10'

#Verificar se o Script está sendo executado como Root#
if [ "$EUID" -ne 0 ]
  then echo "Favor executar como root"
  exit
fi
echo "Iniciando Script de Auditoria "
$SLEEP1
clear
echo "1 Configuração inicial"
echo "1.1 Configuração do Sistema de Arquivos"
echo "1.1.1 Desativar sistemas de arquivos não utilizados"
echo "1.1.1.1 Certifique-se de que a montagem dos sistemas de arquivos do cramfs esteja desabilitada"
modprobe -n -v cramfs
install /bin/true
lsmod | grep cramfs 
#<No output>
echo "verificacao do item 1.1.1.1 OK"

### 1.1.1.2 Certifique-se de que a montagem do sistema de arquivos freevxfs está desabilitada
modprobe -n -v freevxfs
install /bin/true 
lsmod | grep freevxfs 
#<No output>
echo "verificacao do item"
### 1.1.1.3 Certifique-se de que a montagem do sistema de arquivos jffs2 está desabilitada
modprobe -n -v jffs2 
install /bin/true 
lsmod | grep jffs2 
#<No output>
echo "verificacao do item"
### 1.1.1.4 Certifique-se de que a montagem do sistema de arquivos hfs esteja desativada
modprobe -n -v hfs 
install /bin/true 
lsmod | grep hfs 
#<No output>
#echo "1.1.1.5 Certifique-se de que a montagem dos sistemas de arquivos hfsplus está desabilitada"
#echo "1.1.1.6 Certifique-se de que a montagem dos sistemas de arquivos do squashfs está desativada"
#echo "1.1.1.7 Certifique-se de que a montagem dos sistemas de arquivos udf está desativada"
#echo "1.1.1.8 Certifique-se de que a montagem dos sistemas de arquivos FAT está desativada"
#echo "1.1.2 Certifique-se de que a partição separada existe para / tmp"
### 1.1.3 Certifique-se de que a opção nodev seja definida / partição tmp
### 1.1.4 Certifique-se de que a opção nosuid seja definida / partição tmp 
### 1.1.5 Certifique-se de que existe uma partição separada para / var
### 1.1.6 Certifique-se de que existe uma partição separada para / var / tmp
### 1.1.7 Certifique-se de que a opção nodev esteja definida na partição / var / tmp
### 1.1.8 Certifique-se de que a opção nosuid seja definida em / var / tmp partição
### 1.1.9 Certifique-se de que a opção noexec esteja definida na partição / var / tmp
### 1.1.10 Verifique se existe uma partição separada para / var / log
### 1.1.11 Verifique se existe uma partição separada para / var / log / audit
### 1.1.12 Certifique-se de que a partição separada existe para / home
### v1.1.13 Certifique-se de que a opção nodev esteja configurada na partição home / home
### v1.1.14 Certifique-se de que a opção nodev esteja definida na partição / dev / shm
### 1.1.15 Certifique-se de que a opção nosuid seja definida / partição / dev / shm
### 1.1.16 Certifique-se de que a opção noexec esteja configurada na partição / dev / shm
### 1.1.17 Certifique-se de que a opção nodev esteja configurada em partições de mídia removíveis 
### 1.1.18 Certifique-se de que a opção nosuid seja definida em partições de mídia removível 
### 1.1.19 Certifique-se de que a opção noexec esteja configurada em partições de mídia removíveis 
### 1.1.20 Certifique-se de que o bit pegajoso esteja configurado em todos os diretórios com classificação mundial
### 1.1.21 Disable Automounting
### 1.2 Configurar atualizações de software
### 1.2.1 Certifique-se de que os repositórios do gerenciador de pacotes estão configurados
### 1.2.2 Certifique-se de que as chaves GPG estão configuradas 
### 1.3 Controle de integridade do sistema de arquivos
### 1.3.1 Certifique-se de que o AIDE esteja instalado
### 1.3.2 Certifique-se de que a integridade do sistema de arquivos seja regularmente verificada
### 1.4 Configurações de inicialização seguras
### 1.4.1 Assegure-se de que as permissões na configuração do bootloader estão configuradas
### 1.4.2 Certifique-se de que a senha do bootloader esteja configurada
### 1.4.3 Certifique-se de autenticação necessária para o modo de usuário único
### 1.5 Endurecimento adicional do processo
### 1.5.1 Certifique-se de que os despejos do núcleo estejam restritos
### 1.5.2 Certifique-se de que o suporte XD / NX esteja habilitado
### 1.5.3 Certifique-se de que o aleatorizar o layout do espaço de endereço (ASLR) esteja habilitado
### 1.5.4 Certifique-se de que o pré-link esteja desativado 
### 1.6 Controle de acesso obrigatório
### 1.6.1 Configurar o SELinux
### 1.6.1.1 Certifique-se de que o SELinux não está desativado na configuração do carregador de inicialização
### 1.6.1.2 Certifique-se de que o estado SELinux está a aplicar
### 1.6.1.3 Verifique se a política SELinux está configurada
### 1.6.1.4 Certifique-se de que não existem damsons não confinados
### 1.6.2 Configurar AppArmor
### 1.6.2.1 Garanta que o AppArmor não esteja desabilitado na configuração do carregador de inicialização
### 1.6.2.2 Certifique-se de que todos os Perfis AppArmor estão aplicando
### 1.6.3 Certifique-se de que o SELinux ou o AppArmor estão instalados
### 1.7 Banners de aviso
### v1.7.1 Banners de advertência de linha de comando
### 1.7.1.1 Certifique-se de que a mensagem do dia esteja configurada corretamente
### 1.7.1.2 Verifique se o banner de aviso de login local está configurado corretamente
### 1.7.1.3 Certifique-se de que o banner de aviso de login remoto esteja configurado corretamente
### v1.7.1.4 Certifique-se de que as permissões em / etc / motd estão configuradas 
### 1.7.1.5 Certifique-se de que as permissões no / etc / issue estejam configuradas
### 1.7.1.6 Certifique-se de que as permissões no /etc/issue.net estão configuradas 
### 1.7.2 Certifique-se de que o banner de login do GDM esteja configurado
### 1.8 Certifique-se de que as atualizações, os patches e o software de segurança adicional estão instalados
# 2 Serviços
# 2.1 Serviços inetd
### 2.1.1 Certifique-se de que os serviços de carga não estejam habilitados
### 2.1.2 Certifique-se de que os serviços diurnos não estão ativados
### 2.1.3 Certifique-se de que os serviços de descarte não estão habilitados
### 2.1.4 Certifique-se de que os serviços de eco não estejam habilitados
### 2.1.5 Certifique-se de que os serviços de tempo não estão ativados
### 2.1.6 Certifique-se de que o servidor rsh não esteja habilitado
### 2.1.7 Certifique-se de que o servidor de conversação não esteja ativado 
### 2.1.8 Certifique-se de que o servidor telnet não está habilitado
### 2.1.9 Certifique-se de que o servidor tftp não esteja ativado
### 2.1.10 Certifique-se de que o xinetd não está habilitado
### 2.2 Serviços de propósito especial
### 2.2.1 Sincronização de tempo
### 2.2.1.1 Certifique-se de que a sincronização de tempo esteja em uso
### 2.2.1.2 Certifique-se de que ntp esteja configurado
### 2.2.1.3 Certifique-se de que o chrony esteja configurado
### 2.2.2 Certifique-se de que X Window System não esteja instalado
### 2.2.3 Certifique-se de que o Servidor Avahi não esteja habilitado
### 2.2.4 Certifique-se de que CUPS não esteja habilitado
### 2.2.5 Certifique-se de que o Servidor DHCP não esteja habilitado 
### 2.2.6 Certifique-se de que o servidor LDAP não esteja habilitado
### 2.2.7 Certifique-se de que NFS e RPC não estão habilitados
### 2.2.8 Certifique-se de que o Servidor DNS não está habilitado
### 2.2.9 Certifique-se de que o Servidor FTP não está ativado
### 2.2.10 Certifique-se de que o servidor HTTP não está habilitado
### 2.2.11 Certifique-se de que o servidor IMAP e POP3 não está habilitado
### 2.2.12 Certifique-se de que o Samba não está habilitado
### 2.2.13 Certifique-se de que o servidor proxy HTTP não esteja ativado 
### 2.2.14 Certifique-se de que o Servidor SNMP não está habilitado
### 2.2.15 Certifique-se de que o agente de transferência de correio esteja configurado para o modo somente local
### 2.2.16 Certifique-se de que o serviço rsync não esteja ativado
### 2.2.17 Certifique-se de que o NIS Server não está habilitado
### 2.3 Clientes de serviço
### 2.3.1 Garantir que o NIS Client não esteja instalado
### 2.3.2 Certifique-se de que o cliente rsh não esteja instalado
### 2.3.3 Certifique-se de que o cliente de conversação não esteja instalado
### 2.3.4 Certifique-se de que o cliente telnet não está instalado
### 2.3.5 Certifique-se de que o cliente LDAP não esteja instalado
### 3 Configuração de rede
### 3.1 Parâmetros de rede (apenas host)
### 3.1.1 Certifique-se de que o reenvio de IP esteja desabilitado 
### 3.1.2 Certifique-se de que o envio do redirecionamento de pacotes esteja desativado 
### 3.2 Parâmetros de Rede (Host e Roteador)
### 3.2.1 Certifique-se de que os pacotes roteados de origem não são aceitos
### 3.2.2 Certifique-se de que os redirecionamentos ICMP não são aceitos
### 3.2.3 Certifique-se de que os redirecionamentos ICMP seguros não são aceitos
### 3.2.4 Certifique-se de que os pacotes suspeitos estejam registrados
### 3.2.5 Certifique-se de que os pedidos de ICMP de transmissão são ignorados
### 3.2.6 Certifique-se de que as respostas ICMP falsas sejam ignoradas
### 3.2.7 Certifique-se de que o Filtro do caminho reverso está ativado 
### 3.2.8 Certifique-se de que TCP SYN Cookies esteja habilitado
### 3.3 IPv6
### 3.3.1 Certifique-se de que as propagandas do roteador IPv6 não são aceitas 
### 3.3.2 Certifique-se de que os redirecionamentos do IPv6 não são aceitos
### 3.3.3 Certifique-se de que o IPv6 esteja desativado
### 3.4 TCP Wrappers
### 3.4.1 Certifique-se de que o TCP Wrappers esteja instalado
### 3.4.2 Garanta que /etc/hosts.allow esteja configurado
### 3.4.3 Certifique-se de /etc/hosts.deny está configurado
### 3.4.4 Certifique-se de que as permissões em /etc/hosts.allow estão configuradas
### 3.4.5 Certifique-se de que as permissões em /etc/hosts.deny são 644
### 3.5 Protocolos de rede pouco frequentes
### 3.5.1 Certifique-se de que o DCCP esteja desativado
### 3.5.2 Certifique-se de que o SCTP esteja desativado
### 3.5.3 Certifique-se de que o RDS esteja desativado
### 3.5.4 Certifique-se de que TIPC esteja desativado
### 3.6 Configuração do Firewall
### 3.6.1 Certifique-se de que o iptables esteja instalado
### 3.6.2 Certifique-se de que a política de firewall de negação predefinida
### 3.6.3 Certifique-se de que o tráfego de loopback esteja configurado
### 3.6.4 Certifique-se de que as conexões de saída e estabelecidas estão configuradas 
### 3.6.5 Certifique-se de que existam regras de firewall para todas as portas abertas
### 3.7 Certifique-se de que as interfaces sem fio estão desabilitadas 
### 4 Logging and Auditing
### 4.1 Configurar a Contabilidade do Sistema (auditd)
### 4.1.1 Configurar retenção de dados
### 4.1.1.1 Certifique-se de que o tamanho do armazenamento do log de auditoria esteja configurado
### 4.1.1.2 Certifique-se de que o sistema esteja desabilitado quando os logs de auditoria estiverem cheios
### 4.1.1.3 Certifique-se de que os logs de auditoria não sejam excluídos automaticamente
### 4.1.2 Certifique-se de que o serviço de auditoria esteja ativado
### 4.1.3 Certifique-se de que a auditoria dos processos iniciados antes da auditoria esteja habilitada
### 4.1.4 Certifique-se de que os eventos que modificam as informações de data e hora são coletados
### 4.1.5 Certifique-se de que os eventos que modificam as informações do usuário / grupo são coletados
### 4.1.6 Certifique-se de que os eventos que modificam o ambiente de rede do sistema são coletados
### 4.1.7 Certifique-se de que os eventos que modificam os controles de acesso obrigatórios do sistema são coletados (marcados)
### 4.1.8 Certifique-se de que os eventos de login e logout sejam coletados
### 4.1.9 Certifique-se de que as informações de iniciação da sessão sejam coletadas
### 4.1.10 Certifique-se de que os eventos de modificação de permissão de controle de acesso discricionário sejam coletados
### 4.1.11 Certifique-se de que as tentativas de acesso a arquivos não-aprovadas mal sucedidas sejam coletadas
### 4.1.12 Certifique-se de que o uso de comandos privilegiados seja coletado
### 4.1.13 Certifique-se de que as montagens bem sucedidas do sistema de arquivos sejam coletadas
### 4.1.14 Certifique-se de que os eventos de exclusão de arquivos pelos usuários sejam coletados
### 4.1.15 Assegure-se de que as mudanças no escopo de administração do sistema (sudoers) sejam coletadas
### 4.1.16 Certifique-se de que as ações do administrador do sistema (sudolog) sejam coletadas
### 4.1.17 Certifique-se de que o carregamento e descarregamento do módulo do kernel seja coletado
### 4.1.18 Certifique-se de que a configuração da auditoria seja imutável
### 4.2 Configure o registro
### 4.2.1 Configurar rsyslog
### 4.2.1.1 Certifique-se de que rsyslog Service esteja ativado
### 4.2.1.2 Certifique-se de que o log está configurado
### 4.2.1.3 Certifique-se de que as permissões de arquivo padrão do rsyslog estão configuradas
### 4.2.1.4 Certifique-se de que rsyslog esteja configurado para enviar logs para um host de log remoto)
### 4.2.1.5 Certifique-se de que as mensagens rsyslog remotas só são aceitas em hosts de log designados.
### 4.2.2 Configure syslog-ng
### 4.2.2.1 Certifique-se de que o serviço syslog-ng esteja ativado
### 4.2.2.2 Certifique-se de que o log está configurado
### 4.2.2.3 Certifique-se de que as permissões de arquivo padrão do syslog-ng foram configuradas
### 4.2.2.4 Certifique-se de que syslog-ng esteja configurado para enviar logs para um host de log remoto
### 4.2.2.5 Assegure-se de que as mensagens remotas do syslog-ng só são aceitas em hosts de log designados (Não marcados)
### 4.2.3 Certifique-se de que rsyslog ou syslog-ng esteja instalado
### 4.2.4 Certifique-se de que as permissões em todos os arquivos de log estão configuradas
### 4.3 Certifique-se de que Logrotate esteja configurado
### 5 Acesso, Autenticação e Autorização
### 5.1 Configure o cron
### 5.1.1 Certifique-se de que o daemon cron esteja habilitado
### 5.1.2 Certifique-se de que as permissões em / etc / crontab estejam configuradas
### 5.1.3 Certifique-se de que as permissões em /etc/cron.hourly estão configuradas
### 5.1.4 Certifique-se de que as permissões em /etc/cron.daily estão configuradas
### 5.1.5 Certifique-se de que as permissões em /etc/cron.weekly estão configuradas
### 5.1.6 Certifique-se de que as permissões em /etc/cron.monthly estão configuradas
### 5.1.7 Certifique-se de que as permissões em /etc/cron.d estão configuradas
### 5.1.8 Certifique-se de que / cron esteja restrito a usuários autorizados
### 5.2 Configuração do servidor SSH
### 5.2.1 Certifique-se de que as permissões em / etc / ssh / sshd_config estejam configuradas
### 5.2.2 Certifique-se de que o protocolo SSH esteja definido como 2 
### 5.2.3 Certifique-se de que SSH LogLevel esteja configurado para INFO
### 5.2.4 Certifique-se de que o encaminhamento do SSH X11 esteja desabilitado 
### 5.2.5 Certifique-se de que SSH MaxAuthTries esteja configurado para 4 ou menos
### 5.2.6 Certifique-se de que SSH IgnoreRhosts esteja habilitado
### 5.2.7 Certifique-se de que SSH HostbasedAuthentication esteja desativado
### 5.2.8 Certifique-se de que o login do root SSH esteja desativado
### 5.2.9 Certifique-se de que SSH PermitEmptyPasswords esteja desabilitado
### 5.2.10 Certifique-se de que SSH PermitUserEnvironment esteja desativado
### 5.2.11 Certifique-se de que somente os algoritmos MAC aprovados sejam usados ​
### 5.2.12 Certifique-se de que SSH Idle Timeout Interval esteja configurado
### 5.2.13 Certifique-se de que SSH LoginGraceTime esteja configurado para um minuto ou menos
### 5.2.14 Certifique-se de que o acesso SSH é limitado 
### 5.2.15 Certifique-se de que o banner de aviso SSH esteja configurado
### 5.3 Configurar PAM
### 5.3.1 Certifique-se de que os requisitos de criação de senha estão configurados
### 5.3.2 Certifique-se de que o bloqueio para tentativas de senha com falha esteja configurado
### 5.3.3 Certifique-se de que a reutilização de senhas seja limitada
### 5.3.4 Certifique-se de que o algoritmo de hashing de senha seja SHA-512
### 5.4 Contas de usuário e ambiente
### 5.4.1 Definir os Parâmetros do Suite da Senha de Sombra
### 5.4.1.1 Certifique-se de que a expiração da senha é de 90 dias ou menos
### 5.4.1.2 Certifique-se de que os dias mínimos entre as alterações de senha sejam 7 ou mais
### 5.4.1.3 Certifique-se de que os dias de aviso de expiração da senha sejam 7 ou mais
### 5.4.1.4 Certifique-se de que o bloqueio de senha inativo seja de 30 dias ou menos
### 5.4.2 Assegure-se de que as contas do sistema não sejam de login
### 5.4.3 Verifique se o grupo padrão para a conta raiz é GID 0### 
### 5.4.4 Certifique-se de que o umask de usuário padrão seja 027 ou mais restritivo
### 5.5 Certifique-se de que o login do root esteja restrito ao console do sistema
### 5.6 Certifique-se de que o acesso ao comando su esteja restrito 
### 6 Manutenção do sistema
### 6.1 Permissões do arquivo do sistema
### 6.1.1 Permissões do arquivo do sistema de auditoria (Não marcado)
### 6.1.2 Certifique-se de que as permissões no / etc / passwd estão configuradas
### 6.1.3 Certifique-se de que as permissões em / etc / shadow estão configuradas
### 6.1.4 Certifique-se de que as permissões no / etc / group estejam configuradas
### 6.1.5 Certifique-se de que as permissões em / etc / shadow estejam configuradas
### 6.1.6 Certifique-se de que as permissões no / etc / passwd- estão configuradas
### 6.1.7 Certifique-se de que as permissões em / etc / shadow- estão configuradas
### 6.1.8 Certifique-se de que as permissões no / etc / group- estejam configuradas
### 6.1.9 Certifique-se de que as permissões em / etc / gshadow estão configuradas
### 6.1.10 Certifique-se de que não existam arquivos mundiais graváveis ​
### 6.1.11 Certifique-se de que não existam arquivos ou diretórios não possuídos
### 6.1.12 Certifique-se de que não existem arquivos ou diretórios desagrupados
### 6.1.13 Auditoria SUID executáveis ​​(não marcados)
### 6.1.14 Auditoria SGID executáveis ​​(não marcados)
### 6.2 Configurações de Usuário e Grupo
### 6.2.1 Certifique-se de que os campos de senha não estejam vazios
### 6.2.2 Certifique-se de que não existam entradas "+" legadas em / etc / passwd
### 6.2.3 Certifique-se de que não existam entradas "+" legadas em / etc / shadow
### 6.2.4 Certifique-se de que não existam entradas "+" legadas em / etc / group
### 6.2.5 Certifique-se de que a raiz seja a única conta UID 0
### 6.2.6 Certifique-se de integridade da PATH raiz 
### 6.2.7 Certifique-se de que todos os diretórios domésticos de todos os usuários existam
### 6.2.8 Assegure-se de que as permissões dos diretórios domésticos dos usuários sejam 750 ou mais restritivas
### 6.2.9 Certifique-se de que os usuários possuem seus diretórios domésticos
### 6.2.10 Assegure-se de que os arquivos de ponto dos usuários não sejam gravados em grupo ou gravados no mundo
### 6.2.11 Certifique-se de que nenhum usuário tenha arquivos .forward
### 6.2.12 Certifique-se de que nenhum usuário tenha arquivos .netrc
### 6.2.13 Certifique-se de que os arquivos .netrc dos usuários não sejam acessíveis ao grupo ou ao mundo
### 6.2.14 Certifique-se de que nenhum usuário tenha arquivos .rhosts
### 6.2.15 Certifique-se de que todos os grupos em / etc / passwd existem em / etc / group
### 6.2.16 Certifique-se de que não existem UID duplicados
### 6.2.17 Certifique-se de que não existam GID duplicados
### 6.2.18 Certifique-se de que não existam nomes de usuários duplicados
### 6.2.19 Certifique-se de que não existam nomes de grupos duplicados
### 6.2.20 Certifique-se de que o grupo das sombras esteja vazio