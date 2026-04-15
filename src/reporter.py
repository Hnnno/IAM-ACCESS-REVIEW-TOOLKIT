"""
Generación de reportes HTML a partir de la plantilla front.html.
Export a JSON y CSV.
"""

import os
import json
import csv
from datetime import datetime
from .iam_analyzer import Severidad, AnalizadorIAM


_BADGE_CLASS = {
    Severidad.CRITICA: "badge badge-critica",
    Severidad.ALTA:    "badge badge-alta",
    Severidad.MEDIA:   "badge badge-media",
    Severidad.BAJA:    "badge badge-baja",
}

_PLANTILLA_PATH = os.path.join(os.path.dirname(__file__), "..", "front.html")
_CSS_PATH = os.path.join(os.path.dirname(__file__), "..", "static", "report.css")
_JS_PATH  = os.path.join(os.path.dirname(__file__), "..", "static", "report.js")
_MITRE_URL = "https://attack.mitre.org/techniques/{}"


def _cargar_plantilla() -> str:
    with open(_PLANTILLA_PATH, "r", encoding="utf-8") as f:
        plantilla = f.read()
    with open(_CSS_PATH, "r", encoding="utf-8") as f:
        css = f.read()
    with open(_JS_PATH, "r", encoding="utf-8") as f:
        js = f.read()
    return plantilla.replace("%%CSS%%", css).replace("%%JS%%", js)


def _fila(h, idx: int) -> str:
    badge = f'<span class="{_BADGE_CLASS[h.severidad]}">{h.severidad.value}</span>'

    if h.mitre_id:
        tid = h.mitre_id.replace(".", "/")
        mitre_resumen = f'<a class="mitre-tag" href="{_MITRE_URL.format(tid)}" target="_blank">{h.mitre_id}</a>'
        mitre_detalle = (
            f'<div class="detalle-mitre">'
            f'<span class="detalle-lbl">MITRE ATT&CK</span>'
            f'<a class="mitre-link" href="{_MITRE_URL.format(tid)}" target="_blank">{h.mitre_id}</a>'
            f'</div>'
        )
    else:
        mitre_resumen = '<span style="color:#ddd">—</span>'
        mitre_detalle = ""

    resumen = (
        f'<tr class="fila-resumen" data-idx="{idx}" data-sev="{h.severidad.value}" onclick="toggleDetalle({idx})">'
        f'<td>{badge}</td>'
        f'<td>{h.categoria.replace("_", " ")}</td>'
        f'<td style="color:#555;font-size:12px">{h.usuario_id}</td>'
        f'<td>{h.descripcion}</td>'
        f'<td style="text-align:center">{mitre_resumen}</td>'
        f'<td class="col-toggle">▼</td>'
        f'</tr>'
    )

    detalle = (
        f'<tr class="fila-detalle" id="detalle-{idx}">'
        f'<td colspan="6">'
        f'<div class="detalle-grid">'
        f'<div>'
        f'<p class="detalle-lbl">Recomendación</p>'
        f'<p class="detalle-val">{h.recomendacion}</p>'
        f'</div>'
        f'{mitre_detalle}'
        f'</div>'
        f'</td>'
        f'</tr>'
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
        f'<div class="metrica-card sin-aud">'
        f'<span class="num num-sin-aud">{len(fallos)}</span>'
        f'<span class="lbl">Sin auditar</span>'
        f'</div>'
    )

    filas = "".join(
        f'<tr>'
        f'<td>{f.usuario_id}</td>'
        f'<td>{f.control}</td>'
        f'<td>{f.motivo}</td>'
        f'</tr>'
        for f in fallos
    )

    seccion = (
        f'<div class="sin-auditar">'
        f'<div class="sin-auditar-header">Controles no auditados ({len(fallos)})</div>'
        f'<table class="sin-aud-tabla"><tbody>{filas}</tbody></table>'
        f'</div>'
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
    resumen  = analizador.resumen()
    hallazgos = sorted(analizador.hallazgos, key=lambda h: list(Severidad).index(h.severidad))
    metrica_sin_auditar, seccion_sin_auditar = _seccion_sin_auditar(analizador.controles_fallidos)

    total    = resumen["total_hallazgos"]
    criticos = resumen["por_severidad"].get("CRÍTICA", 0)
    altos    = resumen["por_severidad"].get("ALTA", 0)
    medios   = resumen["por_severidad"].get("MEDIA", 0)
    bajos    = resumen["por_severidad"].get("BAJA", 0)

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
        "%%FILAS%%":                "".join(_fila(h, i) for i, h in enumerate(hallazgos)),
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
    directorio = os.path.dirname(ruta) or "."
    os.makedirs(directorio, exist_ok=True)
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