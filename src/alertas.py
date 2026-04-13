"""
Envío de alertas a Slack y Microsoft Teams via webhooks.
Requiere: pip install requests

Configuración:
  Variables de entorno (desarrollo):
    SLACK_WEBHOOK_URL
    TEAMS_WEBHOOK_URL

  O bien, pasar las URLs directamente al instanciar cada cliente.
"""

import os
import logging
import requests
from src.iam_analyzer import AnalizadorIAM, Hallazgo, Severidad

logger = logging.getLogger(__name__)

# Solo se notifican hallazgos de estas severidades por defecto
SEVERIDADES_NOTIFICABLES = {Severidad.CRITICA, Severidad.ALTA}

_EMOJIS = {
    Severidad.CRITICA: "🔴",
    Severidad.ALTA:    "🟠",
    Severidad.MEDIA:   "🟡",
    Severidad.BAJA:    "🔵",
}

_COLORES_HEX = {
    Severidad.CRITICA: "C0392B",
    Severidad.ALTA:    "E67E22",
    Severidad.MEDIA:   "F1C40F",
    Severidad.BAJA:    "95A5A6",
}


def _filtrar(hallazgos: list[Hallazgo], severidades: set[Severidad]) -> list[Hallazgo]:
    return [h for h in hallazgos if h.severidad in severidades]


# ── Slack ──────────────────────────────────────────────────────────────────────

class ClienteSlack:

    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
        if not self.webhook_url:
            raise ValueError(
                "Webhook de Slack no configurado. "
                "Define SLACK_WEBHOOK_URL o pásalo al constructor."
            )

    def enviar(
        self,
        analizador: AnalizadorIAM,
        severidades: set[Severidad] = SEVERIDADES_NOTIFICABLES,
    ) -> bool:
        resumen = analizador.resumen()
        hallazgos = _filtrar(analizador.hallazgos, severidades)

        if not hallazgos:
            logger.info("Slack: sin hallazgos para notificar en las severidades configuradas.")
            return True

        bloques = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🛡️ IAM Access Review — Hallazgos"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Usuarios auditados:*\n{resumen['usuarios_activos']}"},
                    {"type": "mrkdwn", "text": f"*Hallazgos totales:*\n{resumen['total_hallazgos']}"},
                    {"type": "mrkdwn", "text": f"*🔴 Críticos:*\n{resumen['por_severidad'].get('CRÍTICA', 0)}"},
                    {"type": "mrkdwn", "text": f"*🟠 Altos:*\n{resumen['por_severidad'].get('ALTA', 0)}"},
                ],
            },
            {"type": "divider"},
        ]

        for h in hallazgos:
            emoji = _EMOJIS[h.severidad]
            mitre = f"  `{h.mitre_id}`" if h.mitre_id else ""
            bloques.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *[{h.severidad.value}]* {h.categoria.replace('_', ' ')}\n"
                        f"• *Usuario:* `{h.usuario_id}`\n"
                        f"• {h.descripcion}\n"
                        f"• _{h.recomendacion}_{mitre}"
                    ),
                },
            })

        payload = {"blocks": bloques}
        return self._post(payload)

    def _post(self, payload: dict) -> bool:
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info("Slack: alerta enviada correctamente.")
            return True
        except requests.RequestException as e:
            logger.error("Slack: error al enviar alerta: %s", e)
            return False


# ── Microsoft Teams ────────────────────────────────────────────────────────────

class ClienteTeams:

    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or os.environ.get("TEAMS_WEBHOOK_URL")
        if not self.webhook_url:
            raise ValueError(
                "Webhook de Teams no configurado. "
                "Define TEAMS_WEBHOOK_URL o pásalo al constructor."
            )

    def enviar(
        self,
        analizador: AnalizadorIAM,
        severidades: set[Severidad] = SEVERIDADES_NOTIFICABLES,
    ) -> bool:
        resumen = analizador.resumen()
        hallazgos = _filtrar(analizador.hallazgos, severidades)

        if not hallazgos:
            logger.info("Teams: sin hallazgos para notificar en las severidades configuradas.")
            return True

        # Formato Adaptive Card compatible con Teams
        hechos_resumen = [
            {"title": "Usuarios auditados", "value": str(resumen["usuarios_activos"])},
            {"title": "Hallazgos totales",  "value": str(resumen["total_hallazgos"])},
            {"title": "🔴 Críticos", "value": str(resumen["por_severidad"].get("CRÍTICA", 0))},
            {"title": "🟠 Altos",    "value": str(resumen["por_severidad"].get("ALTA", 0))},
        ]

        secciones = [{"facts": hechos_resumen, "markdown": True}]

        for h in hallazgos:
            emoji = _EMOJIS[h.severidad]
            mitre = f" · {h.mitre_id}" if h.mitre_id else ""
            secciones.append({
                "activityTitle": f"{emoji} [{h.severidad.value}] {h.categoria.replace('_', ' ')}",
                "activitySubtitle": f"`{h.usuario_id}`{mitre}",
                "activityText": f"{h.descripcion}<br>_{h.recomendacion}_",
                "markdown": True,
            })

        # Color de la tarjeta según la severidad más alta presente
        severidad_max = min(hallazgos, key=lambda h: list(Severidad).index(h.severidad)).severidad
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": _COLORES_HEX[severidad_max],
            "summary": "IAM Access Review — Hallazgos de seguridad",
            "title": "🛡️ IAM Access Review — Hallazgos",
            "sections": secciones,
        }

        return self._post(payload)

    def _post(self, payload: dict) -> bool:
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info("Teams: alerta enviada correctamente.")
            return True
        except requests.RequestException as e:
            logger.error("Teams: error al enviar alerta: %s", e)
            return False