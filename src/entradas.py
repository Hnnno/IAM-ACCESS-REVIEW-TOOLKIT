"""
Entradas manuales para la auditoría IAM.

Este archivo se carga automáticamente al ejecutar main.py.
Editarlo para agregar usuarios, hallazgos o notas que no provienen
de los conectores automáticos (AWS/Azure).
"""

from datetime import datetime, timedelta
from src.iam_analyzer import Hallazgo, Severidad, Usuario, AccessKey


# ── Usuarios adicionales ───────────────────────────────────────────────────────
# Cuentas que no aparecen en AWS/Azure pero deben auditarse
# (ej: cuentas on-premise, contratistas, cuentas legacy)

USUARIOS_MANUALES: list[Usuario] = [
    # Ejemplo — descomentar y editar:
    # Usuario(
    #     id="ext_001",
    #     nombre="proveedor.externo",
    #     email="proveedor@empresa-externa.com",
    #     roles=["viewer"],
    #     mfa_activo=False,
    #     ultimo_acceso=datetime.now() - timedelta(days=30),
    #     activo=True,
    #     notas_usuario="Contratista de proyecto X. Contrato vence 2026-06-30.",
    # ),
]


# ── Hallazgos manuales ─────────────────────────────────────────────────────────
# Riesgos identificados durante revisión manual que el análisis automático
# no puede detectar (ej: hallazgos de revisión de código, entrevistas, etc.)

HALLAZGOS_MANUALES: list[Hallazgo] = [
    # Ejemplo — descomentar y editar:
    # Hallazgo(
    #     severidad=Severidad.ALTA,
    #     categoria="REVISION_MANUAL",
    #     usuario_id="usr_003",
    #     descripcion="El usuario compartió credenciales con un tercero según reporte del helpdesk.",
    #     recomendacion="Revocar credenciales actuales y generar nuevas. Iniciar proceso disciplinario.",
    #     mitre_id="T1078",
    #     origen="manual",
    # ),
]


# ── Notas sobre usuarios ───────────────────────────────────────────────────────
# Se adjuntan a todos los hallazgos automáticos del usuario indicado.
# Útil para agregar contexto: "en proceso de offboarding", "bajo investigación", etc.

NOTAS: dict[str, str] = {
    # Ejemplo:
    # "usr_002": "Usuario en proceso de offboarding. Acceso debe revocarse antes del 2026-05-01.",
    # "usr_004": "Cuenta de CI/CD en migración. No desactivar hasta completar pipeline.",
}