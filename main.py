"""
Punto de entrada del toolkit.
Uso:
  python main.py                               # datos de demo
  python main.py --fuente aws                  # AWS IAM
  python main.py --fuente azure                # Azure AD
  python main.py --entorno "Prod AWS EU"       # nombre del entorno auditado
  python main.py --responsable "Jane Doe"      # analista responsable
  python main.py --notas "Auditoría trimestral Q2"
  python main.py --exportar json csv           # exports adicionales
  python main.py --slack --teams               # alertas
"""

import sys
import os
import argparse
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(__file__))

from src.iam_analyzer import AnalizadorIAM, Usuario, AccessKey
from src.reporter import generar_html, guardar_reporte, exportar_json, exportar_csv


USUARIOS_DEMO = [
    Usuario(
        id="usr_001", nombre="ana.garcia", email="ana.garcia@corp.com",
        roles=["admin", "developer"], mfa_activo=False,
        ultimo_acceso=datetime.now() - timedelta(days=2),
        activo=True, permisos_directos=[], grupos=["devops"],
        access_keys=[
            AccessKey(
                key_id="AKIAIOSFODNN7EXAMPLE", activa=True,
                creada=datetime.now() - timedelta(days=110),
                ultimo_uso=datetime.now() - timedelta(days=5),
                servicio_ultimo_uso="s3"
            )
        ],
        password_ultima_rotacion=datetime.now() - timedelta(days=400),
        tiene_consola=True, es_cuenta_servicio=False,
    ),
    Usuario(
        id="usr_002", nombre="carlos.mendez", email="carlos.mendez@corp.com",
        roles=["viewer"], mfa_activo=True,
        ultimo_acceso=datetime.now() - timedelta(days=120),
        activo=True, permisos_directos=[], grupos=["soporte"],
        access_keys=[],
        password_ultima_rotacion=datetime.now() - timedelta(days=200),
        tiene_consola=True, es_cuenta_servicio=False,
    ),
    Usuario(
        id="usr_003", nombre="laura.soto", email="laura.soto@corp.com",
        roles=["owner", "billing_admin", "developer", "auditor"],
        mfa_activo=False, ultimo_acceso=None,
        activo=True, permisos_directos=["s3:DeleteBucket", "iam:CreateUser"],
        grupos=[],
        access_keys=[
            AccessKey(
                key_id="AKIAI44QH8DHBEXAMPLE", activa=True,
                creada=datetime.now() - timedelta(days=200),
                ultimo_uso=None, servicio_ultimo_uso=None,
            )
        ],
        password_ultima_rotacion=None,
        tiene_consola=True, es_cuenta_servicio=False,
    ),
    Usuario(
        id="usr_004", nombre="svc-deploy-ci", email="svc-deploy-ci@corp.com",
        roles=["developer"], mfa_activo=True,
        ultimo_acceso=datetime.now() - timedelta(days=1),
        activo=True, permisos_directos=["ec2:TerminateInstances"],
        grupos=["engineering"],
        access_keys=[
            AccessKey(
                key_id="AKIAIOSFODNN8EXAMPLE", activa=True,
                creada=datetime.now() - timedelta(days=95),
                ultimo_uso=datetime.now() - timedelta(days=60),
                servicio_ultimo_uso="ec2"
            )
        ],
        password_ultima_rotacion=datetime.now() - timedelta(days=30),
        tiene_consola=True, es_cuenta_servicio=True,
    ),
    Usuario(
        id="usr_005", nombre="sofia.vargas", email="sofia.vargas@corp.com",
        roles=["superuser"], mfa_activo=True,
        ultimo_acceso=datetime.now() - timedelta(days=1),
        activo=True, permisos_directos=[], grupos=["security"],
        access_keys=[],
        password_ultima_rotacion=datetime.now() - timedelta(days=60),
        tiene_consola=True, es_cuenta_servicio=False,
    ),
    Usuario(
        id="usr_006", nombre="diego.herrera", email="diego.herrera@corp.com",
        roles=["viewer"], mfa_activo=True,
        ultimo_acceso=datetime.now() - timedelta(days=200),
        activo=False, permisos_directos=[], grupos=[],
        access_keys=[], password_ultima_rotacion=None,
        tiene_consola=False, es_cuenta_servicio=False,
    ),
]


def imprimir_resumen_cli(analizador: AnalizadorIAM):
    colores = {
        "CRÍTICA": "\033[91m", "ALTA": "\033[33m",
        "MEDIA":   "\033[93m", "BAJA": "\033[94m",
    }
    reset = "\033[0m"

    print("\n" + "═" * 60)
    print("  IAM ACCESS REVIEW TOOLKIT")
    print("═" * 60)

    r = analizador.resumen()
    print(f"\n  Usuarios: {r['usuarios_activos']} activos / {r['total_usuarios']} totales")
    print(f"  Hallazgos: {r['total_hallazgos']}\n")

    for h in analizador.hallazgos:
        color = colores.get(h.severidad.value, "")
        print(f"  {color}[{h.severidad.value}]{reset} {h.categoria}")
        print(f"         → {h.usuario_id}: {h.descripcion}")
        if h.mitre_id:
            print(f"         → MITRE: {h.mitre_id}")
        print()

    print("═" * 60 + "\n")


def cargar_usuarios(fuente: str, perfil: str = None) -> tuple[list[Usuario], list]:
    if fuente == "demo":
        print("[*] Usando datos de demostración")
        return USUARIOS_DEMO, []

    if fuente == "aws":
        from src.aws_connector import ConectorAWSIAM
        print("[*] Conectando a AWS IAM...")
        conector = ConectorAWSIAM(perfil=perfil)
        usuarios, fallos = conector.obtener_usuarios()
        print(f"[+] {len(usuarios)} usuarios obtenidos de AWS IAM")
        return usuarios, fallos

    if fuente == "azure":
        from src.azure_connector import ConectorAzureAD
        print("[*] Conectando a Azure AD / Entra ID...")
        conector = ConectorAzureAD()
        usuarios, fallos = conector.obtener_usuarios()
        print(f"[+] {len(usuarios)} usuarios obtenidos de Azure AD")
        return usuarios, fallos

    raise ValueError(f"Fuente no reconocida: {fuente}")


def enviar_alertas(analizador: AnalizadorIAM, args: argparse.Namespace):
    if not args.slack and not args.teams:
        return

    from src.alertas import ClienteSlack, ClienteTeams

    if args.slack:
        try:
            ClienteSlack(webhook_url=args.slack_url or None).enviar(analizador)
            print("[+] Alerta enviada a Slack")
        except Exception as e:
            print(f"[!] Slack: {e}")

    if args.teams:
        try:
            ClienteTeams(webhook_url=args.teams_url or None).enviar(analizador)
            print("[+] Alerta enviada a Teams")
        except Exception as e:
            print(f"[!] Teams: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IAM Access Review Toolkit")
    parser.add_argument("--fuente",       choices=["demo", "aws", "azure"], default="demo")
    parser.add_argument("--perfil",       help="Perfil AWS (opcional)", default=None)
    parser.add_argument("--entorno",      help="Nombre del entorno auditado", default="—")
    parser.add_argument("--responsable",  help="Analista responsable de la auditoría", default="—")
    parser.add_argument("--notas",        help="Notas adicionales sobre la auditoría", default="—")
    parser.add_argument("--exportar",     nargs="+", choices=["json", "csv"])
    parser.add_argument("--slack",        action="store_true")
    parser.add_argument("--slack-url",    dest="slack_url", default=None)
    parser.add_argument("--teams",        action="store_true")
    parser.add_argument("--teams-url",    dest="teams_url", default=None)
    args = parser.parse_args()

    try:
        usuarios, fallos_conector = cargar_usuarios(args.fuente, args.perfil)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    analizador = AnalizadorIAM(usuarios)
    analizador.ejecutar_auditoria()
    analizador.controles_fallidos.extend(fallos_conector)

    imprimir_resumen_cli(analizador)

    # El nombre de los archivos se genera con timestamp automáticamente
    html = generar_html(
        analizador,
        entorno_nombre=args.entorno,
        entorno_fuente=args.fuente.upper(),
        entorno_responsable=args.responsable,
        entorno_notas=args.notas,
    )
    ruta_html = guardar_reporte(html)

    # Los exports comparten el mismo timestamp que el HTML
    base = ruta_html.rsplit(".", 1)[0]
    for fmt in (args.exportar or []):
        if fmt == "json":
            exportar_json(analizador, f"{base}.json")
        elif fmt == "csv":
            exportar_csv(analizador, f"{base}.csv")

    enviar_alertas(analizador, args)