"""
Conector AWS IAM — extrae usuarios, roles y políticas via boto3.
Requiere: pip install boto3
Credenciales: perfil ~/.aws/credentials o variables AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
"""

import logging
from datetime import datetime
from typing import Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_DISPONIBLE = True
except ImportError:
    BOTO3_DISPONIBLE = False

from iam_analyzer import Usuario, AccessKey, ControlNoAuditado

logger = logging.getLogger(__name__)

class ConectorAWSIAM:

    POLITICAS_PELIGROSAS = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    }

    def __init__(self, perfil: Optional[str] = None, region: str = "us-east-1"):
        if not BOTO3_DISPONIBLE:
            raise ImportError("boto3 no instalado. Ejecuta: pip install boto3")
        sesion = boto3.Session(profile_name=perfil, region_name=region)
        self.iam = sesion.client("iam")

    def obtener_usuarios(self) -> tuple[list[Usuario], list[ControlNoAuditado]]:
        """
        Retorna (usuarios, controles_fallidos).
        Los controles_fallidos registran qué datos no pudieron recuperarse y por qué.
        """
        usuarios: list[Usuario] = []
        controles_fallidos: list[ControlNoAuditado] = []

        try:
            paginator = self.iam.get_paginator("list_users")
            for pagina in paginator.paginate():
                for raw in pagina["Users"]:
                    usuario, fallos = self._construir_usuario(raw)
                    usuarios.append(usuario)
                    controles_fallidos.extend(fallos)
        except NoCredentialsError:
            raise RuntimeError("Credenciales AWS no configuradas.")
        except ClientError as e:
            raise RuntimeError(f"Error AWS IAM: {e.response['Error']['Message']}") from e

        return usuarios, controles_fallidos

    def _construir_usuario(self, raw: dict) -> tuple[Usuario, list[ControlNoAuditado]]:
        nombre = raw["UserName"]
        user_id = raw["UserId"]
        fallos: list[ControlNoAuditado] = []

        ultimo_acceso, fallo = self._obtener_ultimo_acceso(nombre, raw)
        if fallo:
            fallos.append(fallo)

        roles, fallo = self._obtener_roles_efectivos(nombre, user_id)
        if fallo:
            fallos.append(fallo)

        permisos_directos, fallo = self._obtener_permisos_directos(nombre, user_id)
        if fallo:
            fallos.append(fallo)

        grupos, fallo = self._obtener_grupos(nombre, user_id)
        if fallo:
            fallos.append(fallo)

        mfa_activo, fallo = self._tiene_mfa(nombre, user_id)
        if fallo:
            fallos.append(fallo)

        access_keys, fallo = self._obtener_access_keys(nombre, user_id)
        if fallo:
            fallos.append(fallo)

        # PasswordLastUsed ausente = nunca usó consola o no tiene password de consola
        tiene_consola = "PasswordLastUsed" in raw or raw.get("LoginProfile") is not None
        password_rotacion = self._obtener_password_rotacion(raw)

        # Heurística: nombres con prefijos típicos de service accounts
        prefijos_svc = {"svc-", "srv-", "bot-", "ci-", "sa-", "service-", "system-"}
        es_servicio = any(nombre.lower().startswith(p) for p in prefijos_svc)

        return Usuario(
            id=user_id,
            nombre=nombre,
            email=nombre,
            roles=roles,
            mfa_activo=mfa_activo,
            ultimo_acceso=ultimo_acceso,
            activo=True,
            permisos_directos=permisos_directos,
            grupos=grupos,
            access_keys=access_keys,
            password_ultima_rotacion=password_rotacion,
            tiene_consola=tiene_consola,
            es_cuenta_servicio=es_servicio,
        ), fallos

    def _obtener_password_rotacion(self, raw: dict) -> Optional[datetime]:
        # AWS no expone directamente cuándo cambió el password; usamos CreateDate como límite inferior
        fecha = raw.get("PasswordLastUsed") or raw.get("CreateDate")
        if fecha:
            return fecha.replace(tzinfo=None)
        return None

    def _obtener_ultimo_acceso(
        self, nombre: str, raw: dict
    ) -> tuple[Optional[datetime], Optional[ControlNoAuditado]]:
        if "PasswordLastUsed" in raw:
            return raw["PasswordLastUsed"].replace(tzinfo=None), None

        try:
            resp = self.iam.list_access_keys(UserName=nombre)
            fechas = [
                k["CreateDate"].replace(tzinfo=None)
                for k in resp["AccessKeyMetadata"]
                if k["Status"] == "Active"
            ]
            return (max(fechas) if fechas else None), None
        except ClientError as e:
            motivo = e.response["Error"]["Code"]
            logger.warning("No se pudo obtener último acceso de %s: %s", nombre, motivo)
            return None, ControlNoAuditado(
                usuario_id=nombre,
                control="ultimo_acceso",
                motivo=f"Sin permiso para listar access keys: {motivo}",
            )

    def _obtener_roles_efectivos(
        self, nombre: str, user_id: str
    ) -> tuple[list[str], Optional[ControlNoAuditado]]:
        roles: list[str] = []
        try:
            resp = self.iam.list_attached_user_policies(UserName=nombre)
            for p in resp["AttachedPolicies"]:
                if p["PolicyArn"] in self.POLITICAS_PELIGROSAS:
                    roles.append(p["PolicyName"])

            grupos = self.iam.list_groups_for_user(UserName=nombre)["Groups"]
            for grupo in grupos:
                g_pols = self.iam.list_attached_group_policies(
                    GroupName=grupo["GroupName"]
                )["AttachedPolicies"]
                for p in g_pols:
                    if p["PolicyArn"] in self.POLITICAS_PELIGROSAS:
                        roles.append(f"[via {grupo['GroupName']}] {p['PolicyName']}")

            return roles, None
        except ClientError as e:
            motivo = e.response["Error"]["Code"]
            logger.warning("No se pudieron listar políticas de %s: %s", nombre, motivo)
            return roles, ControlNoAuditado(
                usuario_id=user_id,
                control="politicas_adjuntas",
                motivo=f"Sin permiso para listar políticas: {motivo}. "
                       "El reporte de privilegios puede estar incompleto.",
            )

    def _obtener_permisos_directos(
        self, nombre: str, user_id: str
    ) -> tuple[list[str], Optional[ControlNoAuditado]]:
        try:
            resp = self.iam.list_user_policies(UserName=nombre)
            return resp.get("PolicyNames", []), None
        except ClientError as e:
            motivo = e.response["Error"]["Code"]
            logger.warning("No se pudieron listar permisos inline de %s: %s", nombre, motivo)
            return [], ControlNoAuditado(
                usuario_id=user_id,
                control="permisos_inline",
                motivo=f"Sin permiso para listar políticas inline: {motivo}.",
            )

    def _obtener_grupos(
        self, nombre: str, user_id: str
    ) -> tuple[list[str], Optional[ControlNoAuditado]]:
        try:
            resp = self.iam.list_groups_for_user(UserName=nombre)
            return [g["GroupName"] for g in resp["Groups"]], None
        except ClientError as e:
            motivo = e.response["Error"]["Code"]
            logger.warning("No se pudieron listar grupos de %s: %s", nombre, motivo)
            return [], ControlNoAuditado(
                usuario_id=user_id,
                control="grupos",
                motivo=f"Sin permiso para listar grupos: {motivo}.",
            )

    def _tiene_mfa(
        self, nombre: str, user_id: str
    ) -> tuple[bool, Optional[ControlNoAuditado]]:
        try:
            resp = self.iam.list_mfa_devices(UserName=nombre)
            return len(resp["MFADevices"]) > 0, None
        except ClientError as e:
            motivo = e.response["Error"]["Code"]
            logger.warning("No se pudo verificar MFA de %s: %s", nombre, motivo)
            return False, ControlNoAuditado(
                usuario_id=user_id,
                control="mfa",
                motivo=f"Sin permiso para listar dispositivos MFA: {motivo}. "
                       "El estado de MFA reportado puede no ser confiable.",
            )

    def _obtener_access_keys(
        self, nombre: str, user_id: str
    ) -> tuple[list[AccessKey], Optional[ControlNoAuditado]]:
        try:
            resp = self.iam.list_access_keys(UserName=nombre)
            keys = []
            for k in resp["AccessKeyMetadata"]:
                kid = k["AccessKeyId"]
                # Último uso: requiere llamada separada por key
                ultimo_uso = None
                servicio = None
                try:
                    uso = self.iam.get_access_key_last_used(AccessKeyId=kid)
                    info = uso.get("AccessKeyLastUsed", {})
                    if "LastUsedDate" in info:
                        ultimo_uso = info["LastUsedDate"].replace(tzinfo=None)
                    servicio = info.get("ServiceName")
                except ClientError:
                    pass  # fallo menor: solo perdemos el detalle de último uso

                keys.append(AccessKey(
                    key_id=kid,
                    activa=k["Status"] == "Active",
                    creada=k["CreateDate"].replace(tzinfo=None),
                    ultimo_uso=ultimo_uso,
                    servicio_ultimo_uso=servicio,
                ))
            return keys, None
        except ClientError as e:
            motivo = e.response["Error"]["Code"]
            logger.warning("No se pudieron listar access keys de %s: %s", nombre, motivo)
            return [], ControlNoAuditado(
                usuario_id=user_id,
                control="access_keys",
                motivo=f"Sin permiso para listar access keys: {motivo}. "
                       "La auditoría de rotación de keys no pudo ejecutarse.",
            )