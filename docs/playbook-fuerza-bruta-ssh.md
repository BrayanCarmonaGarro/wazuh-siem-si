# Playbook: Respuesta a incidente de fuerza bruta SSH

**Técnica:** MITRE ATT&CK T1110.001 (Brute Force: Password Guessing)
**Control CIS:** 17 (Gestión de respuesta a incidentes)
**Regla que lo dispara:** `100001` (nivel 10): más de 5 fallos de SSH en 60 s desde la misma IP.

---

## 1. Escenario

| Rol | Máquina | IP |
|---|---|---|
| Atacante | Kali | `192.168.100.99` |
| Víctima (host protegido) | `agent-db` (Debian 12) | `192.168.100.40` |
| SIEM | `wazuh-server` (manager + dashboard) | `192.168.100.10` |

**Cómo funciona el bloqueo.** Kali ataca el SSH de `agent-db`. El agente de Wazuh en `agent-db` envía los fallos de login al manager. El manager dispara la regla 100001 y le ordena a **`agent-db`** que ejecute `firewall-drop`. `agent-db` agrega en **su propio firewall** la regla `DROP 192.168.100.99` durante **600 s**, y luego la quita sola.

> **Cómo leer el dashboard.** `agent.name` es la máquina que **reporta** el evento, o sea la víctima (`agent-db`). La IP del atacante va en `data.srcip` en la alerta 100001, y en `data.parameters.alert.data.srcip` en la 651.

**Responsables**

- **Sebas:** administrador de `agent-db`. Ejecuta los comandos en el host víctima.
- **Brayan:** analista del SIEM. Valida las alertas en el dashboard.
- **Operador de Kali:** lanza el ataque (solo en la prueba o demo).

---

## 2. Preparación (antes del ataque)

### 2.1 Sebas, en `agent-db`

- [ ] **`iptables` instalado.** Debian 12 no lo trae, y sin él `firewall-drop` "se ejecuta" pero **no bloquea nada**. Wazuh igual muestra la alerta 651, así que esa alerta sola no prueba el bloqueo.
  ```bash
  sudo apt update && sudo apt install -y iptables
  which iptables            # debe responder /usr/sbin/iptables
  ```

- [ ] **Los logs de SSH llegan a Wazuh.** Debian 12 guarda los logs en journald y no tiene `/var/log/auth.log`. El `ossec.conf` del agente debe tener este bloque:
  ```bash
  sudo grep -B1 -A2 "journald" /var/ossec/etc/ossec.conf
  ```
  Si no aparece, agregarlo dentro de `<ossec_config>` en `/var/ossec/etc/ossec.conf`:
  ```xml
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>
  ```

- [ ] **El agente lee su propio log de Active Response.** Sin esto, el manager no se entera del bloqueo:
  ```bash
  sudo grep -A1 "active-responses.log" /var/ossec/etc/ossec.conf
  ```
  Si no aparece, agregarlo dentro de `<ossec_config>` en `/var/ossec/etc/ossec.conf`:
  ```xml
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
  ```

- [ ] Si se cambió el `ossec.conf`, reiniciar el agente:
  ```bash
  sudo systemctl restart wazuh-agent
  sudo systemctl status wazuh-agent --no-pager
  ```

- [ ] **Estado inicial del firewall** (primera evidencia: todavía no hay ningún `DROP`):
  ```bash
  sudo iptables -L INPUT -n -v --line-numbers
  ```

### 2.2 Brayan, en `wazuh-server`

- [ ] El bloque `<active-response>` con `firewall-drop`, `<location>local</location>`, `<rules_id>100001</rules_id>` y `<timeout>600</timeout>` está activo en el `ossec.conf` del manager.
- [ ] `192.168.100.99` no aparece en ningún `<white_list>`.
- [ ] `agent-db` aparece como **Active** en el dashboard.

---

## 3. Detección y análisis

### 3.1 El ataque (solo en la prueba o demo, desde Kali)

```bash
# Comprobar que Kali llega al SSH antes del ataque
nc -zv -w 3 192.168.100.40 22          # "open"

# Fuerza bruta. Usar un usuario que EXISTA en agent-db (por ejemplo root).
# Con un usuario inexistente sshd registra "invalid user", que cae en otra
# regla de Wazuh (5710) y la 100001 no se dispara.
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.100.40
```

Si `rockyou.txt` está comprimido: `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`.

### 3.2 Sebas, en `agent-db`: ver el ataque y el bloqueo en vivo

Dejar abierta esta ventana durante el ataque. Se verá aparecer `DROP 192.168.100.99`, y la columna **`pkts`** subirá mientras Kali siga intentando: son paquetes del atacante que el firewall descarta.

```bash
sudo watch -n1 'iptables -L INPUT -n -v --line-numbers | head -5'
```

En otra terminal, los intentos de login que llegan al SSH:

```bash
sudo journalctl -u ssh -f | grep 192.168.100.99
```

### 3.3 Brayan, en el dashboard

- **Threat Hunting → Events**, filtro `rule.id:(100001 OR 651 OR 652)`.
- **100001:** detección de la fuerza bruta. Ahí se toma la IP de origen (`data.srcip`), el usuario atacado y la hora.
- **651:** "Host Blocked by firewall-drop Active Response". Al desplegarla deben verse `agent.name = agent-db`, `data.command = add` y `data.parameters.alert.data.srcip = 192.168.100.99`.

### 3.4 Sebas: ¿hubo algún login exitoso desde el atacante?

Es la pregunta más importante del análisis.

```bash
sudo journalctl -u ssh --since "-1 hour" | grep "Accepted" | grep 192.168.100.99
last -i | grep 192.168.100.99
who
```

- **Sin resultados:** el ataque no tuvo éxito. Seguir con la sección 4.
- **Con resultados:** la cuenta está comprometida. Aplicar la sección 5.2 de inmediato.

---

## 4. Contención (automática)

Wazuh ejecuta `firewall-drop` en `agent-db` sin intervención humana. Sebas **verifica** que el bloqueo es real:

```bash
# 1. La regla existe en el firewall (INPUT y FORWARD)
sudo iptables -L INPUT -n -v --line-numbers | grep 192.168.100.99
sudo iptables -L FORWARD -n -v | grep 192.168.100.99

# 2. El script no dejó errores
sudo grep -iE "error|cannot|unable|not found" /var/ossec/logs/active-responses.log | tail

# 3. No entran intentos nuevos desde el bloqueo (el último "Failed password"
#    debe coincidir con la hora del bloqueo)
sudo journalctl -u ssh --since "-15 min" | grep 192.168.100.99 | tail
```

Desde Kali, la conexión ya no llega:

```bash
nc -zv -w 3 192.168.100.40 22          # ahora: timeout
```

### Si aparece la alerta 651 pero el ataque sigue entrando

| Síntoma | Causa | Qué hacer |
|---|---|---|
| `which iptables` no responde nada, o el log tiene errores | Falta `iptables` | `sudo apt install -y iptables` y repetir el ataque |
| Se bloqueó una IP distinta de `192.168.100.99` | El SSH entra por el NAT de VirtualBox (`10.0.2.x`) | Atacar a `192.168.100.40` por la red puente |
| Hay un `DROP` pero siguen apareciendo `Failed password` desde .99 | Otra regla del firewall deja pasar el tráfico | Revisar `sudo iptables -S` y `sudo nft list ruleset` |
| No aparece la 100001 | Los logs de SSH no llegan, o se atacó un usuario inexistente | Revisar la sección 2.1 y el usuario de hydra |

---

## 5. Erradicación y recuperación

### 5.1 Bloqueo permanente (si la IP se confirma maliciosa)

> ⚠️ **En el laboratorio no aplicarlo antes de terminar los ataques de F5:** dejaría a Kali sin acceso a `agent-db` para el resto de las pruebas.

```bash
sudo iptables -I INPUT -s 192.168.100.99 -j DROP
sudo apt install -y iptables-persistent      # guarda las reglas al reiniciar
sudo netfilter-persistent save
```

Para levantar el bloqueo manualmente (sin esperar los 600 s):

```bash
sudo iptables -D INPUT -s 192.168.100.99 -j DROP
sudo iptables -D FORWARD -s 192.168.100.99 -j DROP
```

### 5.2 Si hubo acceso exitoso (sección 3.4 con resultados)

```bash
# Cerrar las sesiones activas del usuario comprometido
sudo pkill -KILL -u <usuario>

# Cambiar su contraseña
sudo passwd <usuario>

# Revisar si el atacante dejó persistencia
sudo cat /home/<usuario>/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null
sudo crontab -l -u <usuario>
```

### 5.3 Validar la recuperación

- Pasados los 600 s, aparece en el dashboard la alerta **652** ("Host Unblocked").
- `sudo iptables -L INPUT -n` ya no muestra el `DROP`.
- El servicio SSH funciona: `sudo systemctl status ssh --no-pager`.

---

## 6. Actividad post-incidente

### 6.1 Endurecer SSH en `agent-db` (Sebas)

> Se puede aplicar en cualquier momento después de los ataques. Con esta configuración sshd sigue registrando `Failed password for root`, así que la regla 100001 y el bloqueo siguen funcionando, aunque el atacante ya no pueda entrar como root aunque adivine la contraseña. Para revertirlo basta con borrar el archivo y reiniciar `ssh`.

```bash
sudo tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null <<'EOF'
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
EOF
sudo sshd -t && sudo systemctl restart ssh
```

En producción se agrega además `PasswordAuthentication no`, pero solo **después** de configurar el acceso por llaves. Si no, se pierde el acceso. En el laboratorio **no** aplicarlo antes de la demo de F7: sin login por contraseña, hydra no genera `Failed password` y la 100001 no se dispara.

### 6.2 Documentar

Guardar la evidencia en texto y subirla a `evidencias/active-response/` del repositorio. Correr esto en `agent-db` justo después del bloqueo:

```bash
{
  echo "=== $(date '+%F %T') FIREWALL DURANTE EL ATAQUE (agent-db) ==="
  sudo iptables -L INPUT -n -v --line-numbers
  echo
  echo "=== ULTIMOS INTENTOS SSH DESDE KALI ==="
  sudo journalctl -u ssh --since "-15 min" | grep 192.168.100.99 | tail -n 8
  echo
  echo "=== REGISTRO DE WAZUH (active-responses.log) ==="
  sudo grep firewall-drop /var/ossec/logs/active-responses.log \
    | grep -oE '^[0-9/]+ [0-9:]+|"command":"(add|delete)"|"srcip":"[^"]+"' | paste - - - | tail
} | tee ar-08-bloqueo-real-agent-db.txt
```

Repetirlo después de los 600 s con el nombre `ar-09-desbloqueo-real-agent-db.txt`, para registrar el desbloqueo.

### 6.3 Lecciones aprendidas

- ¿El umbral (más de 5 fallos en 60 s) detectó el ataque a tiempo? ¿Hubo falsos positivos?
- ¿El tiempo de bloqueo (600 s) es suficiente, o conviene escalar a un bloqueo permanente cuando la misma IP reincide?
- Registrar la hora de detección, la de bloqueo y la de desbloqueo, para medir el tiempo de respuesta.

---

## 7. Resumen de evidencias para F4

| # | Qué se muestra | Dónde | Quién |
|---|---|---|---|
| 1 | Firewall sin reglas y Kali con el puerto 22 abierto | `agent-db` + Kali | Sebas |
| 2 | hydra en ejecución | Kali | Operador de Kali |
| 3 | Aparece `DROP 192.168.100.99` con `pkts` subiendo | `agent-db` (`watch`) | Sebas |
| 4 | `nc` desde Kali da timeout | Kali | Operador de Kali |
| 5 | Alertas 100001 y 651 (desplegada, con la IP bloqueada) | Dashboard | Brayan |
| 6 | No hubo logins exitosos desde .99 | `agent-db` (`journalctl` / `last`) | Sebas |
| 7 | A los 600 s: alerta 652, firewall limpio, Kali vuelve a conectar | Dashboard + `agent-db` | Brayan + Sebas |
