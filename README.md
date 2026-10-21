# wazuh-siem-si
Proyecto Final Seguridad Informática UNA 2026: SIEM con Wazuh, reglas MITRE ATT&amp;CK, Active Response y cumplimiento CIS

## Estructura del repositorio

```
wazuh-siem-si/
├── rules/
├── decoders/
└── evidencias/
    ├── logtest/
    ├── alertas/
    └── active-response/
```

| Carpeta | Para qué es |
|---------|-------------|
| `rules/` | Reglas personalizadas de Wazuh (`local_rules.xml`) con su mapeo MITRE ATT&CK y nivel de severidad: fuerza bruta SSH, modificación de `/etc/passwd` o `/etc/sudoers`, `sudo` por usuario no privilegiado, conexión al puerto 4444, creación de cuentas en Windows fuera de horario, escaneo de puertos y escalada de privilegios (Event ID 7045). En el manager se copian a `/var/ossec/etc/rules/`. |
| `decoders/` | Decodificadores personalizados para los logs de **Apache** (detección de inyección SQL) y **PostgreSQL** (autenticaciones fallidas y consultas sospechosas). Permiten que Wazuh extraiga los campos que evalúan las reglas. En el manager se copian a `/var/ossec/etc/decoders/`. |
| `evidencias/` | Pruebas de que las reglas, los decodificadores y la respuesta activa funcionan. |
| `evidencias/logtest/` | Capturas de `wazuh-logtest` que muestran que cada regla y decodificador hace match con un log de ejemplo, con el nivel y la técnica MITRE esperados. |
| `evidencias/alertas/` | Capturas del dashboard de Wazuh con las alertas que generaron los ataques reales, con el nivel y la técnica MITRE visibles. |
| `evidencias/active-response/` | Capturas del bloqueo automático de la IP atacante (`firewall-drop`) cuando se dispara una regla de nivel alto. |
