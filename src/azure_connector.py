"""
Conector Azure AD / Entra ID — extrae usuarios via Microsoft Graph API.
Requiere: pip install requests msal
Configuración: App Registration en Azure con permisos:
  - User.Read.All
  - Directory.Read.All
  - UserAuthenticationMethod.Read.All
"""

from datetime import datetime
from typing import Optional

try:
    import requests
    import msal
    MSAL_DISPONIBLE = True
except ImportError:
    MSAL_DISPONIBLE = False

from src.iam_analyzer import Usuario


GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

ROLES_PRIVILEGIADOS_AZURE = {
    "Global Administrator",
    "Privileged Role Administrator",
    "User Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
}


class ConectorAzureAD:

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        if not MSAL_DISPONIBLE:
            raise ImportError("Dependencias faltantes. Ejecuta: pip install requests msal")

        self.tenant_id = tenant_id
        self._token = self._autenticar(tenant_id, client_id, client_secret)
        self._headers = {"Authorization": f"Bearer {self._token}"}

    def _autenticar(self, tenant_id: str, client_id: str, client_secret: str) -> str:
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        resultado = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        if "access_token" not in resultado:
            raise RuntimeError(f"Error de autenticación Azure: {resultado.get('error_description')}")
        return resultado["access_token"]

    def obtener_usuarios(self) -> list[Usuario]:
        usuarios_raw = self._paginar(
            f"{GRAPH_BASE}/users",
            params={
                "$select": "id,displayName,userPrincipalName,accountEnabled,signInActivity,assignedRoles",
                "$top": "999",
            }
        )
        roles_por_usuario = self._mapear_roles_por_usuario()

        return [
            self._construir_usuario(u, roles_por_usuario.get(u["id"], []))
            for u in usuarios_raw
        ]

    def _construir_usuario(self, raw: dict, roles: list[str]) -> Usuario:
        ultimo_acceso = self._parsear_fecha(
            raw.get("signInActivity", {}).get("lastSignInDateTime")
        )
        mfa = self._tiene_mfa(raw["id"])

        return Usuario(
            id=raw["id"],
            nombre=raw.get("displayName", ""),
            email=raw.get("userPrincipalName", ""),
            roles=roles,
            mfa_activo=mfa,
            ultimo_acceso=ultimo_acceso,
            activo=raw.get("accountEnabled", False),
            permisos_directos=[],
            grupos=self._obtener_grupos(raw["id"]),
        )

    def _mapear_roles_por_usuario(self) -> dict[str, list[str]]:
        """Construye un mapa user_id → lista de roles asignados."""
        mapa: dict[str, list[str]] = {}
        roles_dir = self._paginar(f"{GRAPH_BASE}/directoryRoles")

        for rol in roles_dir:
            nombre_rol = rol.get("displayName", "")
            miembros = self._paginar(
                f"{GRAPH_BASE}/directoryRoles/{rol['id']}/members",
                params={"$select": "id"}
            )
            for miembro in miembros:
                uid = miembro["id"]
                mapa.setdefault(uid, []).append(nombre_rol)

        return mapa

    def _tiene_mfa(self, user_id: str) -> bool:
        try:
            resp = requests.get(
                f"{GRAPH_BETA}/users/{user_id}/authentication/methods",
                headers=self._headers,
                timeout=10
            )
            if resp.status_code != 200:
                return False
            metodos = resp.json().get("value", [])
            # Cualquier método que no sea solo contraseña indica MFA configurado
            tipos_mfa = {
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
                "#microsoft.graph.phoneAuthenticationMethod",
                "#microsoft.graph.fido2AuthenticationMethod",
            }
            return any(m.get("@odata.type") in tipos_mfa for m in metodos)
        except requests.RequestException:
            return False

    def _obtener_grupos(self, user_id: str) -> list[str]:
        try:
            resp = requests.get(
                f"{GRAPH_BASE}/users/{user_id}/memberOf",
                headers=self._headers,
                params={"$select": "displayName"},
                timeout=10
            )
            if resp.status_code != 200:
                return []
            return [g.get("displayName", "") for g in resp.json().get("value", [])]
        except requests.RequestException:
            return []

    def _paginar(self, url: str, params: Optional[dict] = None) -> list[dict]:
        resultados = []
        while url:
            resp = requests.get(url, headers=self._headers, params=params, timeout=15)
            resp.raise_for_status()
            datos = resp.json()
            resultados.extend(datos.get("value", []))
            url = datos.get("@odata.nextLink")
            params = None  # solo en la primera llamada
        return resultados

    @staticmethod
    def _parsear_fecha(fecha_str: Optional[str]) -> Optional[datetime]:
        if not fecha_str:
            return None
        try:
            return datetime.fromisoformat(fecha_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None