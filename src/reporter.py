"""
Generación de reportes HTML a partir de la plantilla front.html.
"""

import os
from datetime import datetime
from .iam_analyzer import Severidad, AnalizadorIAM


_COLORES = {
    Severidad.CRITICA: "color:#c0392b;font-weight:600",
    Severidad.ALTA:    "color:#e67e22;font-weight:600",
    Severidad.MEDIA:   "color:#8a6d00;font-weight:600",
    Severidad.BAJA:    "color:#555;font-weight:600",
}

_PLANTILLA_PATH = os.path.join(os.path.dirname(__file__), "..", "front.html")


def _cargar_plantilla() -> str:
    with open(_PLANTILLA_PATH, "r", encoding="utf-8") as f:
        return f.read()


def _fila(h) -> str:
    mitre = f'<span style="color:#888;font-size:11px">{h.mitre_id}</span>' if h.mitre_id else "—"
    return (
        f"<tr>"
        f"<td><span style='{_COLORES[h.severidad]}'>{h.severidad.value}</span></td>"
        f"<td>{h.categoria.replace('_', ' ')}</td>"
        f"<td style='color:#555'>{h.usuario_id}</td>"
        f"<td>{h.descripcion}</td>"
        f"<td style='color:#444'>{h.recomendacion}</td>"
        f"<td style='text-align:center'>{mitre}</td>"
        f"</tr>"
    )


def _seccion_sin_auditar(fallos: list) -> tuple[str, str]:
    """Retorna (metrica_html, seccion_html) para los controles no auditados."""
    if not fallos:
        return "", ""

    metrica = (
        f"<div class='metrica'>"
        f"<span class='num' style='color:#c0392b'>{len(fallos)}</span>"
        f"<span class='lbl'>Sin auditar</span>"
        f"</div>"
    )

    filas = "".join(
        f"<tr>"
        f"<td style='color:#555;font-size:11px'>{f.usuario_id}</td>"
        f"<td style='font-size:11px'>{f.control}</td>"
        f"<td style='color:#888;font-size:11px'>{f.motivo}</td>"
        f"</tr>"
        for f in fallos
    )

    seccion = (
        f"<div class='sin-auditar'>"
        f"<p class='lbl-seccion'>Controles no auditados ({len(fallos)})</p>"
        f"<table><thead><tr>"
        f"<th style='width:120px'>Usuario</th>"
        f"<th style='width:140px'>Control</th>"
        f"<th>Motivo</th>"
        f"</tr></thead><tbody>{filas}</tbody></table>"
        f"</div>"
    )

    return metrica, seccion


def generar_html(analizador: AnalizadorIAM, titulo: str = "IAM Access Review") -> str:
    resumen = analizador.resumen()
    hallazgos = sorted(analizador.hallazgos, key=lambda h: list(Severidad).index(h.severidad))
    metrica_sin_auditar, seccion_sin_auditar = _seccion_sin_auditar(analizador.controles_fallidos)

    valores = {
        "%%TITULO%%":              titulo,
        "%%FECHA%%":               datetime.now().strftime("%d %b %Y, %H:%M"),
        "%%USUARIOS_ACTIVOS%%":    str(resumen["usuarios_activos"]),
        "%%USUARIOS_TOTALES%%":    str(resumen["total_usuarios"]),
        "%%TOTAL%%":               str(resumen["total_hallazgos"]),
        "%%CRITICOS%%":            str(resumen["por_severidad"].get("CRÍTICA", 0)),
        "%%ALTOS%%":               str(resumen["por_severidad"].get("ALTA", 0)),
        "%%MEDIOS%%":              str(resumen["por_severidad"].get("MEDIA", 0)),
        "%%BAJOS%%":               str(resumen["por_severidad"].get("BAJA", 0)),
        "%%FILAS%%":               "".join(_fila(h) for h in hallazgos),
        "%%METRICA_SIN_AUDITAR%%": metrica_sin_auditar,
        "%%SECCION_SIN_AUDITAR%%": seccion_sin_auditar,
    }

    plantilla = _cargar_plantilla()
    for token, valor in valores.items():
        plantilla = plantilla.replace(token, valor)
    return plantilla


def guardar_reporte(html: str, ruta: str = "reports/reporte_iam.html"):
    os.makedirs(os.path.dirname(ruta) or ".", exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Reporte guardado en: {ruta}")