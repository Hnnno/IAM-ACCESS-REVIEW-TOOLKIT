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