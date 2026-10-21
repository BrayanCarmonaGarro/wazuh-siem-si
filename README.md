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
