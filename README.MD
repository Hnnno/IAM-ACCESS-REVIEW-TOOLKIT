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

Requisitos
Python 3.9 o superior.

Dependencias: boto3, msal, requests.

Bash
pip install -r requirements.txt

Configuración y Seguridad
La herramienta permite la integración con gestores de secretos (AWS Secrets Manager / Azure Key Vault) para el manejo de credenciales de API. Se recomienda el uso de roles de solo lectura (ReadOnlyAccess) para la ejecución del scanner.

Uso
Simulación (Demo)

Bash
python main.py --fuente demo

AWS
Bash
python main.py --fuente aws --perfil nombre_perfil

Azure
Requiere las variables de entorno: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.
Bash
python main.py --fuente azure

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

## Próximas integraciones

- [ ] Conector LDAP / Active Directory
- [ ] Export a JSON/CSV
- [ ] Envío de alertas por Slack/Teams