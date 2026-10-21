# wazuh-siem-si
Proyecto Final Seguridad Informática UNA 2026: SIEM con Wazuh, reglas MITRE ATT&amp;CK, Active Response y cumplimiento CIS

## Estructura del repositorio

```
wazuh-siem-si/
├── rules/
├── decoders/
├── docs/
└── evidencias/
    ├── logtest/
    ├── alertas/
    └── active-response/
```

| Carpeta | Para qué es |
|---------|-------------|
| `rules/` | Reglas personalizadas de Wazuh (`local_rules.xml`) con su mapeo MITRE ATT&CK y nivel de severidad: fuerza bruta SSH, modificación de `/etc/passwd` o `/etc/sudoers`, `sudo` por usuario no privilegiado, conexión al puerto 4444, creación de cuentas en Windows fuera de horario, escaneo de puertos y escalada de privilegios (Event ID 7045). En el manager se copian a `/var/ossec/etc/rules/`. |
| `decoders/` | Decodificadores personalizados para los logs de **Apache** (detección de inyección SQL) y **PostgreSQL** (autenticaciones fallidas y consultas sospechosas). Permiten que Wazuh extraiga los campos que evalúan las reglas. En el manager se copian a `/var/ossec/etc/decoders/`. |
| `docs/` | Archivos de configuración del SIEM, comentados. `ossec.conf` es la configuración del manager: FIM (syscheck) sobre `/etc`, `/bin` y `/usr/bin`, rootcheck, logcollector y el comando `firewall-drop` de Active Response; en el manager está en `/var/ossec/etc/ossec.conf`. `agent.conf` es la configuración centralizada que el manager envía a los agentes: FIM sobre `/etc`, `/bin`, `/usr/bin`, `/var/www` y `C:\Windows\System32`, y la recolección de logs de Apache y PostgreSQL; en el manager está en `/var/ossec/etc/shared/default/agent.conf`. `ism-retencion-90d.json` es la política de retención del Wazuh Indexer (ISM, el equivalente de ILM en OpenSearch): conserva los índices `wazuh-alerts-*` y `wazuh-archives-*` durante 90 días y luego los elimina. |
| `evidencias/` | Pruebas de que las reglas, los decodificadores y la respuesta activa funcionan. |
| `evidencias/logtest/` | Capturas de `wazuh-logtest` que muestran que cada regla y decodificador hace match con un log de ejemplo, con el nivel y la técnica MITRE esperados. |
| `evidencias/alertas/` | Capturas del dashboard de Wazuh con las alertas que generaron los ataques reales, con el nivel y la técnica MITRE visibles. |
| `evidencias/active-response/` | Capturas del bloqueo automático de la IP atacante (`firewall-drop`) cuando se dispara una regla de nivel alto. |

## Cómo aplicar las reglas y los decodificadores en el manager

Los archivos de este repositorio son la copia de trabajo; el manager los lee desde `/var/ossec/etc/`. Para aplicar cualquier cambio:

```bash
# 1. Copiar los archivos a su ubicación en el manager
sudo cp rules/local_rules.xml       /var/ossec/etc/rules/local_rules.xml
sudo cp decoders/local_decoder.xml  /var/ossec/etc/decoders/local_decoder.xml

# 2. Permisos (si no son correctos, el manager no arranca)
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/decoders/local_decoder.xml
sudo chmod 660         /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/decoders/local_decoder.xml

# 3. Validar la sintaxis ANTES de reiniciar
sudo /var/ossec/bin/wazuh-analysisd -t

# 4. Reiniciar el manager y comprobar que quedó arriba
sudo systemctl restart wazuh-manager
sudo systemctl status  wazuh-manager
```

**Orden de carga:** el manager lee primero los decodificadores y reglas de fábrica (`/var/ossec/ruleset/`) y después los personalizados (`/var/ossec/etc/`). Por eso los decodificadores de este repositorio se escriben como **hijos** (`<parent>`) de los de fábrica cuando estos ya hacen match: así añaden campos sin tener que excluir el original en el bloque `<ruleset>` del `ossec.conf`.

**Probar una regla o un decodificador:**

```bash
sudo /var/ossec/bin/wazuh-logtest        # pegar una línea de evidencias/logtest/muestras-logtest.txt
sudo /var/ossec/bin/wazuh-logtest -v     # igual, pero mostrando el detalle de la fase de decodificación
```

La salida tiene tres fases: **1** el log tal cual, **2** el decodificador que hizo match y los campos extraídos, **3** la regla que disparó con su nivel y su técnica MITRE. Las capturas de esa salida son la evidencia de `evidencias/logtest/`.

> Las reglas de FIM (100002) no se pueden probar con `wazuh-logtest`, porque los eventos de FIM no son líneas de log: se validan en vivo sobre el propio manager (agente 000), que ya vigila `/etc` en tiempo real.
