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
_MITRE_URL = "https://attack.mitre.org/techniques/{}"


_CSS = """
/* ── Reset ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --critica:    #c0392b;
  --critica-bg: #fdf2f1;
  --alta:       #c0550a;
  --alta-bg:    #fef3eb;
  --media:      #8a6d00;
  --media-bg:   #fdf8e1;
  --baja:       #555e68;
  --baja-bg:    #f2f3f4;
  --border:     #e8e8e8;
  --bg-alt:     #f7f8f9;
  --text:       #111;
  --text-dim:   #888;
  --radius:     5px;
  --shadow:     0 1px 3px rgba(0,0,0,.06);
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  font-size: 13px;
  color: var(--text);
  background: #f4f5f7;
  line-height: 1.5;
}

.page { max-width: 1160px; margin: 0 auto; padding: 40px 40px 64px; }

/* ── Header ── */
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.header-marca { display: flex; align-items: center; gap: 10px; }

.header-icono {
  width: 30px; height: 30px;
  background: var(--text);
  border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
}

.header h1 { font-size: 15px; font-weight: 700; letter-spacing: -0.2px; }

.header-meta { text-align: right; font-size: 11px; color: var(--text-dim); line-height: 1.7; }

/* ── Entorno ── */
.entorno {
  display: flex;
  background: #fff;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow: hidden;
  margin-bottom: 16px;
}

.entorno-campo { flex: 1; padding: 11px 18px; border-right: 1px solid var(--border); min-width: 0; }
.entorno-campo:last-child { border-right: none; }
.entorno-campo .lbl { font-size: 9px; text-transform: uppercase; letter-spacing: 1px; color: #bbb; font-weight: 600; margin-bottom: 3px; }
.entorno-campo .val { font-size: 12px; font-weight: 600; color: #333; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* ── Panel superior ── */
.panel-superior { display: grid; grid-template-columns: 210px 1fr; gap: 14px; margin-bottom: 14px; }

/* ── Métricas ── */
.metricas-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }

.metrica-card {
  background: #fff;
  border: 1px solid var(--border);
  border-left: 3px solid transparent;
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 12px 14px;
  display: flex; flex-direction: column; gap: 2px;
}

.metrica-card.total    { grid-column: span 2; border-left-color: var(--text); }
.metrica-card.critica  { border-left-color: var(--critica); }
.metrica-card.alta     { border-left-color: var(--alta); }
.metrica-card.media    { border-left-color: var(--media); }
.metrica-card.baja     { border-left-color: var(--baja); }
.metrica-card.sin-aud  { border-left-color: var(--critica); grid-column: span 2; }

.metrica-card .num { font-size: 28px; font-weight: 800; line-height: 1; letter-spacing: -1px; }
.metrica-card .lbl { font-size: 9px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-dim); font-weight: 600; }

.num-total   { color: var(--text); }
.num-critica { color: var(--critica); }
.num-alta    { color: var(--alta); }
.num-media   { color: var(--media); }
.num-baja    { color: var(--baja); }
.num-sin-aud { color: var(--critica); }

/* ── Gráfico ── */
.grafico-card {
  background: #fff;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 18px 22px;
  display: flex; flex-direction: column; justify-content: center;
}

.grafico-titulo { font-size: 9px; text-transform: uppercase; letter-spacing: 1px; color: #bbb; font-weight: 600; margin-bottom: 14px; }

.barras { display: flex; flex-direction: column; gap: 11px; }

.barra-fila { display: flex; align-items: center; gap: 10px; }

.barra-lbl { font-size: 11px; color: #666; width: 52px; text-align: right; flex-shrink: 0; }

.barra-track { flex: 1; height: 8px; background: #efefef; border-radius: 99px; overflow: hidden; }

.barra-fill { height: 100%; border-radius: 99px; width: 0%; transition: width 0.7s cubic-bezier(.4,0,.2,1); }

.barra-cnt { font-size: 11px; color: var(--text-dim); width: 24px; text-align: right; flex-shrink: 0; font-variant-numeric: tabular-nums; }

/* ── Sección tabla ── */
.tabla-section {
  background: #fff;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow: hidden;
}

.tabla-toolbar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-alt);
}

.tabla-toolbar-titulo { font-size: 9px; text-transform: uppercase; letter-spacing: 1px; color: #bbb; font-weight: 600; }

.contador { font-size: 11px; color: var(--text-dim); }

/* ── Filtros ── */
.filtros { display: flex; gap: 5px; }

.filtro-btn {
  padding: 3px 11px; font-size: 11px; font-family: inherit;
  border: 1px solid var(--border); border-radius: 99px;
  background: #fff; cursor: pointer; color: #666; font-weight: 500;
  transition: all 0.15s; line-height: 1.6;
}

.filtro-btn:hover { background: #efefef; }
.filtro-btn.activo                     { background: var(--text);    color: #fff; border-color: var(--text); }
.filtro-btn[data-sev="CRÍTICA"].activo { background: var(--critica); color: #fff; border-color: var(--critica); }
.filtro-btn[data-sev="ALTA"].activo    { background: var(--alta);    color: #fff; border-color: var(--alta); }
.filtro-btn[data-sev="MEDIA"].activo   { background: var(--media);   color: #fff; border-color: var(--media); }
.filtro-btn[data-sev="BAJA"].activo    { background: var(--baja);    color: #fff; border-color: var(--baja); }

/* ── Tabla ── */
.tabla-wrap { overflow-x: auto; }

table { width: 100%; border-collapse: collapse; }

thead th {
  font-size: 9px; text-transform: uppercase; letter-spacing: 1px;
  color: #bbb; font-weight: 600; text-align: left;
  padding: 9px 14px; border-bottom: 1px solid var(--border);
  white-space: nowrap; background: var(--bg-alt);
}

tbody td { padding: 11px 14px; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }

.fila-resumen { cursor: pointer; transition: background 0.1s; }
.fila-resumen:hover td { background: #fafbfc; }
.fila-resumen.expandida td { background: var(--bg-alt); }

/* ── Badge ── */
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 3px;
  font-size: 10px; font-weight: 700; letter-spacing: 0.3px; white-space: nowrap;
}

.badge-critica { background: var(--critica-bg); color: var(--critica); }
.badge-alta    { background: var(--alta-bg);    color: var(--alta); }
.badge-media   { background: var(--media-bg);   color: var(--media); }
.badge-baja    { background: var(--baja-bg);    color: var(--baja); }

/* ── MITRE ── */
.mitre-tag {
  display: inline-block; font-size: 10px; color: #888; background: #f0f0f0;
  padding: 2px 7px; border-radius: 3px; text-decoration: none; font-weight: 500;
  transition: background 0.1s;
}
.mitre-tag:hover { background: #e2e2e2; color: #555; }

/* ── Toggle ── */
.col-toggle { color: #ccc; font-size: 10px; text-align: right; padding-right: 14px !important; user-select: none; }

/* ── Detalle ── */
.fila-detalle { display: none; }
.fila-detalle.abierto { display: table-row; }

.fila-detalle td { background: var(--bg-alt); border-bottom: 2px solid var(--border); padding: 0; }

.detalle-inner {
  padding: 14px 20px;
  display: grid; grid-template-columns: 1fr auto; gap: 20px; align-items: start;
}

.detalle-lbl { font-size: 9px; text-transform: uppercase; letter-spacing: 1px; color: #bbb; font-weight: 600; margin-bottom: 4px; }
.detalle-val { font-size: 12px; color: #333; line-height: 1.6; }

.detalle-mitre-wrap { display: flex; flex-direction: column; align-items: flex-end; gap: 4px; }
.detalle-mitre-wrap .detalle-lbl { text-align: right; }

.mitre-link {
  font-size: 11px; font-weight: 600; color: #555; background: #e8e8e8;
  padding: 4px 10px; border-radius: 3px; text-decoration: none; transition: background 0.1s;
}
.mitre-link:hover { background: #d8d8d8; }

/* ── Sin auditar ── */
.sin-auditar {
  background: #fff; border: 1px solid var(--border);
  border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; margin-top: 14px;
}

.sin-auditar-header {
  padding: 10px 14px; background: var(--bg-alt); border-bottom: 1px solid var(--border);
  font-size: 9px; text-transform: uppercase; letter-spacing: 1px; color: #bbb; font-weight: 600;
}

.sin-aud-tabla td { font-size: 11px; color: var(--text-dim); padding: 9px 14px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
.sin-aud-tabla td:first-child  { color: #555; font-weight: 500; white-space: nowrap; width: 120px; }
.sin-aud-tabla td:nth-child(2) { white-space: nowrap; width: 140px; }
.sin-aud-tabla tr:last-child td { border-bottom: none; }

/* ── Footer ── */
footer { margin-top: 28px; font-size: 11px; color: #ccc; display: flex; justify-content: space-between; }

/* ── Filtrado ── */
.fila-resumen.filtrada { display: none; }
.fila-detalle.filtrada { display: none !important; }

/* ── Badge manual ── */
.badge-manual {
  display: inline-block;
  margin-left: 5px;
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.5px;
  background: #e8f4fd;
  color: #1a6fa8;
  vertical-align: middle;
}

/* ── Nota del analista en detalle ── */
.detalle-nota {
  margin-top: 10px;
  padding: 8px 10px;
  background: #fffbea;
  border-left: 2px solid #f0c040;
  border-radius: 0 3px 3px 0;
}

.detalle-nota .detalle-lbl { color: #b8860b; }
.detalle-nota .detalle-val { color: #5a4a00; }
"""

_JS = """
(function () {
  "use strict";

  window.toggleDetalle = function (idx) {
    var fila   = document.getElementById("detalle-" + idx);
    var btn    = document.querySelector("[data-idx='" + idx + "']");
    var toggle = btn.querySelector(".col-toggle");
    var open   = fila.classList.toggle("abierto");
    btn.classList.toggle("expandida", open);
    toggle.textContent = open ? "▲" : "▼";
  };

  function animarBarras() {
    document.querySelectorAll(".barra-fill[data-w]").forEach(function (el) {
      el.style.width = el.dataset.w + "%";
    });
  }

  function actualizarContador() {
    var total   = document.querySelectorAll(".fila-resumen").length;
    var visibles = document.querySelectorAll(".fila-resumen:not(.filtrada)").length;
    var el = document.getElementById("contador");
    if (el) el.textContent = visibles === total ? total + " hallazgos" : visibles + " de " + total;
  }

  function filtrar(sev) {
    document.querySelectorAll(".fila-resumen").forEach(function (fila) {
      var det    = document.getElementById("detalle-" + fila.dataset.idx);
      var oculta = sev && fila.dataset.sev !== sev;

      fila.classList.toggle("filtrada", oculta);
      if (det) det.classList.toggle("filtrada", oculta);

      if (oculta && det) {
        det.classList.remove("abierto");
        fila.classList.remove("expandida");
        var t = fila.querySelector(".col-toggle");
        if (t) t.textContent = "▼";
      }
    });
    actualizarContador();
  }

  document.addEventListener("DOMContentLoaded", function () {
    setTimeout(animarBarras, 50);
    actualizarContador();

    document.querySelectorAll(".filtro-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var sev     = this.dataset.sev;
        var activo  = this.classList.contains("activo");

        document.querySelectorAll(".filtro-btn").forEach(function (b) { b.classList.remove("activo"); });

        if (!activo) { this.classList.add("activo"); filtrar(sev); }
        else { filtrar(null); }
      });
    });
  });
})();
"""


def _cargar_plantilla() -> str:
    with open(_PLANTILLA_PATH, "r", encoding="utf-8") as f:
        plantilla = f.read()
    return plantilla.replace("%%CSS%%", _CSS).replace("%%JS%%", _JS)


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