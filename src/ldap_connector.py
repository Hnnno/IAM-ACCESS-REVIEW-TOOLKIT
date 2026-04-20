"""
Conector LDAP / Active Directory — extrae usuarios via ldap3.
Requiere: pip install ldap3

Configuración mínima:
  LDAP_HOST     servidor AD (ej: "dc01.corp.local" o "ldap://192.168.1.10")
  LDAP_USER     cuenta de lectura (ej: "corp\\auditor" o "auditor@corp.local")
  LDAP_PASSWORD contraseña
  LDAP_BASE_DN  base de búsqueda (ej: "DC=corp,DC=local")

Variables de entorno opcionales:
  LDAP_PORT     (por defecto 389, o 636 para LDAPS)
  LDAP_USE_SSL  "true" para LDAPS
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Optional

try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES
    from ldap3.core.exceptions import LDAPException, LDAPBindError
    LDAP3_DISPONIBLE = True
except ImportError:
    LDAP3_DISPONIBLE = False

from src.iam_analyzer import Usuario, ControlNoAuditado

logger = logging.getLogger(__name__)

# Atributos AD a recuperar por usuario
_ATRIBUTOS = [
    "objectGUID",
    "sAMAccountName",
    "userPrincipalName",
    "displayName",
    "userAccountControl",
    "lastLogonTimestamp",
    "pwdLastSet",
    "memberOf",
    "adminCount",
    "servicePrincipalName",   # presente → cuenta de servicio
    "msDS-User-Account-Control-Computed",
]

# Flags de userAccountControl relevantes
_UAC_DISABLED          = 0x0002
_UAC_PASSWD_NOTREQD    = 0x0020
_UAC_SMARTCARD_REQUIRED = 0x40000  # proxy para MFA en AD

# Grupos que se consideran privilegiados (nombres en minúsculas)
_GRUPOS_PRIVILEGIADOS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "group policy creator owners",
}

# Windows FILETIME epoch (100-nanosecond intervals desde 1601-01-01)
_FILETIME_EPOCH = datetime(1601, 1, 1)
_FILETIME_NEVER = 0


def _filetime_a_datetime(filetime: int) -> Optional[datetime]:
    if not filetime or filetime in (_FILETIME_NEVER, 9223372036854775807):
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)


class ConectorLDAP:

    def __init__(
        self,
        host: Optional[str]     = None,
        user: Optional[str]     = None,
        password: Optional[str] = None,
        base_dn: Optional[str]  = None,
        port: Optional[int]     = None,
        use_ssl: bool           = False,
    ):
        if not LDAP3_DISPONIBLE:
            raise ImportError("ldap3 no instalado. Ejecuta: pip install ldap3")

        self.host     = host     or os.environ["LDAP_HOST"]
        self.user     = user     or os.environ["LDAP_USER"]
        self.password = password or os.environ["LDAP_PASSWORD"]
        self.base_dn  = base_dn  or os.environ["LDAP_BASE_DN"]
        self.use_ssl  = use_ssl  or os.environ.get("LDAP_USE_SSL", "").lower() == "true"
        self.port     = port     or int(os.environ.get("LDAP_PORT", 636 if self.use_ssl else 389))

    def obtener_usuarios(self) -> tuple[list[Usuario], list[ControlNoAuditado]]:
        """Retorna (usuarios, controles_fallidos)."""
        try:
            conn = self._conectar()
        except LDAPBindError as e:
            raise RuntimeError(f"Error de autenticación LDAP: {e}") from e
        except LDAPException as e:
            raise RuntimeError(f"Error de conexión LDAP: {e}") from e

        usuarios: list[Usuario]                  = []
        controles_fallidos: list[ControlNoAuditado] = []

        conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectClass=user)(objectCategory=person))",
            search_scope=SUBTREE,
            attributes=_ATRIBUTOS,
        )

        for entrada in conn.entries:
            usuario, fallos = self._construir_usuario(entrada)
            if usuario:
                usuarios.append(usuario)
            controles_fallidos.extend(fallos)

        conn.unbind()
        return usuarios, controles_fallidos

    def _conectar(self) -> "Connection":
        servidor = Server(self.host, port=self.port, use_ssl=self.use_ssl, get_info=ALL)
        conn = Connection(
            servidor,
            user=self.user,
            password=self.password,
            authentication=NTLM,
            auto_bind=True,
        )
        return conn

    def _construir_usuario(
        self, entrada
    ) -> tuple[Optional[Usuario], list[ControlNoAuditado]]:
        fallos: list[ControlNoAuditado] = []

        try:
            sam = str(entrada.sAMAccountName)
            uid = str(entrada.objectGUID)
        except Exception:
            return None, []

        # ── Estado de la cuenta ───────────────────────────────────────────────
        uac = int(entrada.userAccountControl.value or 0)
        activo = not bool(uac & _UAC_DISABLED)

        # ── Email ─────────────────────────────────────────────────────────────
        email = str(entrada.userPrincipalName.value or sam)

        # ── Último acceso ─────────────────────────────────────────────────────
        ultimo_acceso, fallo = self._obtener_ultimo_acceso(entrada, uid)
        if fallo:
            fallos.append(fallo)

        # ── Password ──────────────────────────────────────────────────────────
        pwd_last_set = _filetime_a_datetime(int(entrada.pwdLastSet.value or 0))

        # ── Grupos y roles ────────────────────────────────────────────────────
        grupos  = self._extraer_grupos(entrada)
        roles   = self._detectar_roles_privilegiados(entrada, grupos)

        # ── MFA — AD usa "SmartCard required" como señal de autenticación fuerte
        mfa_activo = bool(uac & _UAC_SMARTCARD_REQUIRED)

        # ── Cuenta de servicio ────────────────────────────────────────────────
        tiene_spn     = bool(entrada.servicePrincipalName.value)
        es_servicio   = tiene_spn or any(
            sam.lower().startswith(p)
            for p in {"svc", "srv", "bot", "sa-", "service", "system"}
        )

        return Usuario(
            id=uid,
            nombre=sam,
            email=email,
            roles=roles,
            mfa_activo=mfa_activo,
            ultimo_acceso=ultimo_acceso,
            activo=activo,
            permisos_directos=[],   # AD no expone permisos directos vía LDAP base
            grupos=grupos,
            password_ultima_rotacion=pwd_last_set,
            tiene_consola=True,     # en AD todos los usuarios pueden iniciar sesión por defecto
            es_cuenta_servicio=es_servicio,
        ), fallos

    def _obtener_ultimo_acceso(
        self, entrada, uid: str
    ) -> tuple[Optional[datetime], Optional[ControlNoAuditado]]:
        try:
            raw = entrada.lastLogonTimestamp.value
            return _filetime_a_datetime(int(raw or 0)), None
        except Exception as e:
            logger.warning("No se pudo leer lastLogonTimestamp de %s: %s", uid, e)
            return None, ControlNoAuditado(
                usuario_id=uid,
                control="ultimo_acceso",
                motivo=f"No se pudo leer lastLogonTimestamp: {e}",
            )

    def _extraer_grupos(self, entrada) -> list[str]:
        grupos = []
        raw = entrada.memberOf.value
        if not raw:
            return grupos
        # raw puede ser str o lista
        items = [raw] if isinstance(raw, str) else list(raw)
        for dn in items:
            # Extraer CN del DN: "CN=Domain Admins,CN=Users,DC=corp,DC=local"
            partes = dn.split(",")
            if partes:
                cn = partes[0].removeprefix("CN=").removeprefix("cn=")
                grupos.append(cn)
        return grupos

    def _detectar_roles_privilegiados(self, entrada, grupos: list[str]) -> list[str]:
        roles = []

        # adminCount=1 indica que el objeto fue tocado por AdminSDHolder (privilegiado)
        admin_count = int(entrada.adminCount.value or 0)
        if admin_count == 1:
            roles.append("admin")

        for grupo in grupos:
            if grupo.lower() in _GRUPOS_PRIVILEGIADOS:
                roles.append(grupo)

        return roles