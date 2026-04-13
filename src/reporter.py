"""
Generación de reportes HTML a partir de la plantilla front.html.
Export a JSON y CSV.
"""

import os
import json
import csv
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
    """Genera una fila expandible: resumen visible + detalle oculto."""
    mitre_resumen = f'<span style="color:#888;font-size:11px">{h.mitre_id}</span>' if h.mitre_id else "—"
    mitre_detalle = f'<span class="detalle-mitre">{h.mitre_id}</span>' if h.mitre_id else ""

    resumen = (
        f"<tr>"
        f"<td><button class='fila-resumen'>"
        f"<span class='col-sev'><span style='{_COLORES[h.severidad]}'>{h.severidad.value}</span></span>"
        f"<span class='col-cat'>{h.categoria.replace('_', ' ')}</span>"
        f"<span class='col-usr'>{h.usuario_id}</span>"
        f"<span class='col-desc'>{h.descripcion}</span>"
        f"<span class='col-mitre'>{mitre_resumen}</span>"
        f"<span class='col-toggle'>▼</span>"
        f"</button></td>"
        f"</tr>"
    )

    detalle = (
        f"<tr><td>"
        f"<div class='detalle'>"
        f"<p class='detalle-lbl'>Recomendación</p>"
        f"<p class='detalle-val'>{h.recomendacion}</p>"
        f"{mitre_detalle}"
        f"</div>"
        f"</td></tr>"
    )

    return resumen + detalle


def _pct(valor: int, total: int) -> int:
    if total == 0:
        return 0
    return round(valor * 100 / total)


def _seccion_sin_auditar(fallos: list) -> tuple[str, str]:
    if not fallos:
        return "", ""

    metrica = (
        f"<div class='metrica'>"
        f"<span class='num' style='color:#c0392b'>{len(fallos)}</span>"
        f"<span class='lbl'>Sin auditar</span>"
        f"</div>"
    )

    filas = "".join(
        f"<tr><td><button class='fila-resumen'>"
        f"<span class='col-cat'>{f.usuario_id}</span>"
        f"<span class='col-usr'>{f.control}</span>"
        f"<span class='col-desc' style='color:#888'>{f.motivo}</span>"
        f"</button></td></tr>"
        for f in fallos
    )

    seccion = (
        f"<div class='sin-auditar'>"
        f"<p class='lbl-seccion'>Controles no auditados ({len(fallos)})</p>"
        f"<table><tbody>{filas}</tbody></table>"
        f"</div>"
    )

    return metrica, seccion


def _nombre_con_timestamp(base: str = "reports/reporte_iam", ext: str = "html") -> str:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"{base}_{ts}.{ext}"


def generar_html(
    analizador: AnalizadorIAM,
    titulo: str = "IAM Access Review",
    entorno_nombre: str = "—",
    entorno_fuente: str = "—",
    entorno_responsable: str = "—",
    entorno_notas: str = "—",
) -> str:
    resumen = analizador.resumen()
    hallazgos = sorted(analizador.hallazgos, key=lambda h: list(Severidad).index(h.severidad))
    metrica_sin_auditar, seccion_sin_auditar = _seccion_sin_auditar(analizador.controles_fallidos)

    total     = resumen["total_hallazgos"]
    criticos  = resumen["por_severidad"].get("CRÍTICA", 0)
    altos     = resumen["por_severidad"].get("ALTA", 0)
    medios    = resumen["por_severidad"].get("MEDIA", 0)
    bajos     = resumen["por_severidad"].get("BAJA", 0)

    valores = {
        "%%TITULO%%":               titulo,
        "%%FECHA%%":                datetime.now().strftime("%d %b %Y, %H:%M"),
        "%%USUARIOS_ACTIVOS%%":     str(resumen["usuarios_activos"]),
        "%%USUARIOS_TOTALES%%":     str(resumen["total_usuarios"]),
        "%%TOTAL%%":                str(total),
        "%%CRITICOS%%":             str(criticos),
        "%%ALTOS%%":                str(altos),
        "%%MEDIOS%%":               str(medios),
        "%%BAJOS%%":                str(bajos),
        "%%PCT_CRITICA%%":          str(_pct(criticos, total)),
        "%%PCT_ALTA%%":             str(_pct(altos, total)),
        "%%PCT_MEDIA%%":            str(_pct(medios, total)),
        "%%PCT_BAJA%%":             str(_pct(bajos, total)),
        "%%FILAS%%":                "".join(_fila(h) for h in hallazgos),
        "%%METRICA_SIN_AUDITAR%%":  metrica_sin_auditar,
        "%%SECCION_SIN_AUDITAR%%":  seccion_sin_auditar,
        "%%ENTORNO_NOMBRE%%":       entorno_nombre,
        "%%ENTORNO_FUENTE%%":       entorno_fuente,
        "%%ENTORNO_RESPONSABLE%%":  entorno_responsable,
        "%%ENTORNO_NOTAS%%":        entorno_notas,
    }

    plantilla = _cargar_plantilla()
    for token, valor in valores.items():
        plantilla = plantilla.replace(token, valor)
    return plantilla


def guardar_reporte(html: str, ruta: str | None = None) -> str:
    if ruta is None:
        ruta = _nombre_con_timestamp("reports/reporte_iam", "html")
    os.makedirs(os.path.dirname(ruta) or ".", exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Reporte HTML guardado en: {ruta}")
    return ruta


# ── Export ─────────────────────────────────────────────────────────────────────

def exportar_json(analizador: AnalizadorIAM, ruta: str | None = None) -> str:
    if ruta is None:
        ruta = _nombre_con_timestamp("reports/reporte_iam", "json")
    os.makedirs(os.path.dirname(ruta) or ".", exist_ok=True)
    resumen = analizador.resumen()
    datos = {
        "generado":  resumen["timestamp"],
        "resumen":   resumen,
        "hallazgos": [
            {
                "severidad":     h.severidad.value,
                "categoria":     h.categoria,
                "usuario_id":    h.usuario_id,
                "descripcion":   h.descripcion,
                "recomendacion": h.recomendacion,
                "mitre_id":      h.mitre_id,
            }
            for h in analizador.hallazgos
        ],
        "controles_no_auditados": [
            {"usuario_id": c.usuario_id, "control": c.control, "motivo": c.motivo}
            for c in analizador.controles_fallidos
        ],
    }
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)
    print(f"[+] JSON exportado en: {ruta}")
    return ruta


def exportar_csv(analizador: AnalizadorIAM, ruta: str | None = None) -> str:
    if ruta is None:
        ruta = _nombre_con_timestamp("reports/reporte_iam", "csv")
    os.makedirs(os.path.dirname(ruta) or ".", exist_ok=True)
    campos = ["severidad", "categoria", "usuario_id", "descripcion", "recomendacion", "mitre_id"]
    with open(ruta, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        for h in analizador.hallazgos:
            writer.writerow({
                "severidad":     h.severidad.value,
                "categoria":     h.categoria,
                "usuario_id":    h.usuario_id,
                "descripcion":   h.descripcion,
                "recomendacion": h.recomendacion,
                "mitre_id":      h.mitre_id or "",
            })
    print(f"[+] CSV exportado en: {ruta}")
    return ruta