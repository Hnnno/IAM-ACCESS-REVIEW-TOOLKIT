"""
IAM Access Review Toolkit
Motor de análisis de identidades y accesos.
"""

from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severidad(Enum):
    CRITICA = "CRÍTICA"
    ALTA    = "ALTA"
    MEDIA   = "MEDIA"
    BAJA    = "BAJA"


@dataclass
class AccessKey:
    key_id: str
    activa: bool
    creada: datetime
    ultimo_uso: Optional[datetime]
    servicio_ultimo_uso: Optional[str] = None


@dataclass
class Usuario:
    id: str
    nombre: str
    email: str
    roles: list[str]
    mfa_activo: bool
    ultimo_acceso: Optional[datetime]
    activo: bool
    permisos_directos: list[str]       = field(default_factory=list)
    grupos: list[str]                  = field(default_factory=list)
    access_keys: list[AccessKey]       = field(default_factory=list)
    password_ultima_rotacion: Optional[datetime] = None
    tiene_consola: bool                = True
    es_cuenta_servicio: bool           = False
    # Campo libre para metadata adicional visible en el reporte
    notas_usuario: Optional[str]       = None


@dataclass
class Hallazgo:
    severidad: Severidad
    categoria: str
    usuario_id: str
    descripcion: str
    recomendacion: str
    mitre_id: Optional[str] = None
    # Campos para entradas manuales
    origen: str            = "automatico"   # "automatico" | "manual"
    nota: Optional[str]    = None           # comentario libre del analista


@dataclass
class ControlNoAuditado:
    """Registra controles que no pudieron ejecutarse por falta de permisos."""
    usuario_id: str
    control: str
    motivo: str


class AnalizadorIAM:
    """Motor principal de análisis de accesos."""

    DIAS_INACTIVIDAD_UMBRAL  = 90
    DIAS_ROTACION_KEY        = 90
    DIAS_KEY_SIN_USO         = 45
    DIAS_ROTACION_PASSWORD   = 365
    ROLES_PRIVILEGIADOS      = {"admin", "superuser", "root", "owner", "god_mode"}
    PREFIJOS_CUENTA_SERVICIO = {"svc-", "srv-", "bot-", "ci-", "sa-", "service-", "system-"}

    def __init__(self, usuarios: list[Usuario]):
        self.usuarios: list[Usuario]             = list(usuarios)
        self.hallazgos: list[Hallazgo]           = []
        self.controles_fallidos: list[ControlNoAuditado] = []

    # ── API pública para entradas manuales ────────────────────────────────────

    def agregar_usuario_manual(self, usuario: Usuario) -> None:
        """Añade un usuario que no viene de ningún conector."""
        self.usuarios.append(usuario)

    def agregar_hallazgo_manual(self, hallazgo: Hallazgo) -> None:
        """
        Registra un hallazgo identificado manualmente por el analista.
        El hallazgo debe tener origen='manual'.
        """
        hallazgo.origen = "manual"
        self.hallazgos.append(hallazgo)

    def agregar_nota(self, usuario_id: str, nota: str) -> None:
        """
        Agrega una nota a todos los hallazgos existentes de un usuario.
        Llamar después de ejecutar_auditoria().
        """
        for h in self.hallazgos:
            if h.usuario_id == usuario_id:
                h.nota = nota

    # ── Análisis automático ───────────────────────────────────────────────────

    def ejecutar_auditoria(self) -> list[Hallazgo]:
        # Solo resetea los hallazgos automáticos; los manuales añadidos antes se preservan
        automaticos_previos = [h for h in self.hallazgos if h.origen == "manual"]
        self.hallazgos      = automaticos_previos
        self.controles_fallidos = []

        for usuario in self.usuarios:
            if not usuario.activo:
                continue
            self._verificar_mfa(usuario)
            self._verificar_inactividad(usuario)
            self._verificar_privilegios_excesivos(usuario)
            self._verificar_permisos_directos(usuario)
            self._verificar_roles_multiples(usuario)
            self._verificar_access_keys(usuario)
            self._verificar_rotacion_password(usuario)
            self._verificar_cuenta_servicio_interactiva(usuario)

        return self.hallazgos

    def _verificar_mfa(self, usuario: Usuario):
        if not usuario.mfa_activo:
            privilegiado = any(r.lower() in self.ROLES_PRIVILEGIADOS for r in usuario.roles)
            self.hallazgos.append(Hallazgo(
                severidad=Severidad.CRITICA if privilegiado else Severidad.ALTA,
                categoria="MFA",
                usuario_id=usuario.id,
                descripcion=f"{usuario.email} no tiene MFA habilitado",
                recomendacion="Habilitar MFA inmediatamente. Forzar via política.",
                mitre_id="T1078",
            ))

    def _verificar_inactividad(self, usuario: Usuario):
        if usuario.ultimo_acceso is None:
            self.hallazgos.append(Hallazgo(
                severidad=Severidad.ALTA,
                categoria="INACTIVIDAD",
                usuario_id=usuario.id,
                descripcion=f"{usuario.email} nunca ha iniciado sesión",
                recomendacion="Deshabilitar cuenta o requerir activación con verificación.",
                mitre_id="T1078.004",
            ))
            return
        dias = (datetime.now() - usuario.ultimo_acceso).days
        if dias > self.DIAS_INACTIVIDAD_UMBRAL:
            self.hallazgos.append(Hallazgo(
                severidad=Severidad.MEDIA,
                categoria="INACTIVIDAD",
                usuario_id=usuario.id,
                descripcion=f"{usuario.email} inactivo por {dias} días",
                recomendacion="Revisar si la cuenta sigue siendo necesaria. Deshabilitar si no.",
                mitre_id="T1078",
            ))

    def _verificar_privilegios_excesivos(self, usuario: Usuario):
        peligrosos = [r for r in usuario.roles if r.lower() in self.ROLES_PRIVILEGIADOS]
        if peligrosos:
            self.hallazgos.append(Hallazgo(
                severidad=Severidad.ALTA,
                categoria="PRIVILEGIO_EXCESIVO",
                usuario_id=usuario.id,
                descripcion=f"{usuario.email} posee rol(es) de alto privilegio: {peligrosos}",
                recomendacion="Aplicar principio de mínimo privilegio. Revisar si el rol es justificado.",
                mitre_id="T1078.003",
            ))

    def _verificar_permisos_directos(self, usuario: Usuario):
        if usuario.permisos_directos:
            self.hallazgos.append(Hallazgo(
                severidad=Severidad.MEDIA,
                categoria="PERMISOS_DIRECTOS",
                usuario_id=usuario.id,
                descripcion=f"{usuario.email} tiene {len(usuario.permisos_directos)} permiso(s) asignados directamente",
                recomendacion="Migrar permisos a grupos o roles. Eliminar asignaciones directas.",
            ))

    def _verificar_roles_multiples(self, usuario: Usuario):
        if len(usuario.roles) >= 4:
            self.hallazgos.append(Hallazgo(
                severidad=Severidad.BAJA,
                categoria="ACUMULACION_ROLES",
                usuario_id=usuario.id,
                descripcion=f"{usuario.email} acumula {len(usuario.roles)} roles",
                recomendacion="Revisar si todos los roles son necesarios. Posible privilege creep.",
                mitre_id="T1098",
            ))

    def _verificar_access_keys(self, usuario: Usuario):
        hoy = datetime.now()
        for key in usuario.access_keys:
            if not key.activa:
                continue
            dias_creada = (hoy - key.creada).days
            if dias_creada > self.DIAS_ROTACION_KEY:
                self.hallazgos.append(Hallazgo(
                    severidad=Severidad.ALTA,
                    categoria="ACCESS_KEY_ANTIGUA",
                    usuario_id=usuario.id,
                    descripcion=f"{usuario.email}: key ...{key.key_id[-4:]} sin rotar hace {dias_creada} días",
                    recomendacion=f"Rotar la access key. Implementar rotación automática cada {self.DIAS_ROTACION_KEY} días.",
                    mitre_id="T1552.001",
                ))
            if key.ultimo_uso is not None:
                dias_uso = (hoy - key.ultimo_uso).days
                if dias_uso > self.DIAS_KEY_SIN_USO:
                    self.hallazgos.append(Hallazgo(
                        severidad=Severidad.MEDIA,
                        categoria="ACCESS_KEY_INACTIVA",
                        usuario_id=usuario.id,
                        descripcion=f"{usuario.email}: key ...{key.key_id[-4:]} activa pero sin uso hace {dias_uso} días",
                        recomendacion="Revocar la key si no está en uso activo.",
                        mitre_id="T1078",
                    ))
            elif dias_creada > self.DIAS_KEY_SIN_USO:
                self.hallazgos.append(Hallazgo(
                    severidad=Severidad.MEDIA,
                    categoria="ACCESS_KEY_INACTIVA",
                    usuario_id=usuario.id,
                    descripcion=f"{usuario.email}: key ...{key.key_id[-4:]} nunca usada, creada hace {dias_creada} días",
                    recomendacion="Revocar la key si no corresponde a una integración pendiente.",
                    mitre_id="T1078",
                ))

    def _verificar_rotacion_password(self, usuario: Usuario):
        if usuario.password_ultima_rotacion is None:
            return
        dias = (datetime.now() - usuario.password_ultima_rotacion).days
        if dias > self.DIAS_ROTACION_PASSWORD:
            self.hallazgos.append(Hallazgo(
                severidad=Severidad.MEDIA,
                categoria="PASSWORD_ANTIGUA",
                usuario_id=usuario.id,
                descripcion=f"{usuario.email}: contraseña sin cambiar hace {dias} días",
                recomendacion=f"Forzar cambio de contraseña. Rotación máxima recomendada: {self.DIAS_ROTACION_PASSWORD} días.",
                mitre_id="T1110",
            ))

    def _verificar_cuenta_servicio_interactiva(self, usuario: Usuario):
        parece_servicio = any(usuario.nombre.lower().startswith(p) for p in self.PREFIJOS_CUENTA_SERVICIO)
        if (usuario.es_cuenta_servicio or parece_servicio) and usuario.tiene_consola:
            self.hallazgos.append(Hallazgo(
                severidad=Severidad.ALTA,
                categoria="CUENTA_SERVICIO_CONSOLA",
                usuario_id=usuario.id,
                descripcion=f"{usuario.email}: cuenta de servicio con acceso interactivo a consola habilitado",
                recomendacion="Deshabilitar el acceso a consola. Las cuentas de servicio solo deben operar via API/keys.",
                mitre_id="T1078.004",
            ))

    def resumen(self) -> dict:
        conteo = {s: 0 for s in Severidad}
        for h in self.hallazgos:
            conteo[h.severidad] += 1
        manuales = sum(1 for h in self.hallazgos if h.origen == "manual")
        return {
            "total_usuarios":        len(self.usuarios),
            "usuarios_activos":      sum(1 for u in self.usuarios if u.activo),
            "total_hallazgos":       len(self.hallazgos),
            "hallazgos_manuales":    manuales,
            "por_severidad":         {s.value: n for s, n in conteo.items()},
            "controles_no_auditados": len(self.controles_fallidos),
            "timestamp":             datetime.now().isoformat(),
        }