IAM Access Review Toolkit
Herramienta de auditoría de identidades para entornos AWS y Azure AD orientada a la detección de riesgos y cumplimiento del principio de mínimo privilegio.

Descripción
El toolkit automatiza la revisión de configuraciones de acceso, evaluando la postura de seguridad de las identidades frente a vectores de ataque comunes. Los hallazgos se categorizan por severidad y se vinculan a técnicas de la matriz MITRE ATT&CK.

Funcionalidades
Extracción de datos de usuarios, roles y permisos de AWS (Boto3) y Azure (Graph API).
Identificación de cuentas con MFA inactivo o inactividad prolongada.
Detección de acumulación de privilegios (Privilege Creep) y permisos directos.
Registro de errores de auditoría para evitar falsos negativos por falta de visibilidad.
Generación de reportes técnicos en formato HTML.

Los controles que no pudieron ejecutarse por falta de permisos se registran explícitamente en el reporte, en lugar de silenciarse.

Alertas
Las alertas se envían via webhook y notifican únicamente hallazgos de severidad CRÍTICA y ALTA para evitar ruido. Configurar mediante variables de entorno o flags:
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
export TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...

Requisitos
Python 3.9 o superior.

Dependencias: boto3, msal, requests.

Bash
pip install -r requirements.txt

Configuración y Seguridad
La herramienta permite la integración con gestores de secretos (AWS Secrets Manager / Azure Key Vault) para el manejo de credenciales de API. Se recomienda el uso de roles de solo lectura (ReadOnlyAccess) para la ejecución del scanner.

Uso
Datos de demostración:
python main.py --fuente demo
AWS IAM: 
python main.py --fuente aws
python main.py --fuente aws --perfil nombre-perfil
Azure AD:
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
python main.py --fuente azure
Exportar resultados:
python main.py --fuente aws --exportar json
python main.py --fuente aws --exportar csv
Configuración de alertas:
python main.py --fuente aws --slack
python main.py --fuente aws --teams
python main.py --fuente aws --slack --slack-url https://hooks.slack.com/...

Estructura del Proyecto
src/iam_analyzer.py: Lógica central de análisis y definiciones de riesgo.
src/aws.py: Conector para servicios de identidad de AWS.
src/azure.py: Conector para Microsoft Entra ID.
src/reporter.py: Generador de reportes.
main.py: Punto de entrada de la aplicación.

Clasificación de Hallazgos
Los hallazgos se reportan bajo los siguientes niveles:
CRITICA: Riesgos inmediatos (ej. Administrador sin MFA).
ALTA: Configuraciones inseguras con alto impacto.
MEDIA: Desviaciones de mejores prácticas.
BAJA: Observaciones de higiene de identidad.
INFO/ERROR: Fallos en la recolección de datos que requieren revisión manual.

Información adicional: En caso de hacer reportes, estos se irán añadiendo en formato .html en la carpeta reports.