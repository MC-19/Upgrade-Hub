nmap 10.10.38.140 --scaneo de la ip

nmap -vv -sV -A -O -sC -p 135,139,445,3389 10.10.38.140 --scaneo de los purtos abiertos y sistema operativo

nmap --script smb-vuln-ms17-010 -p445 10.10.38.140 --scaneo para saber si la maquina es vulnerable a este excploit tras la verison del sistema operativo

