# app.py
import os
import traceback
from flask import Flask, jsonify, send_from_directory, request
import sys

# asegurar path para imports locales
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.append(ROOT)

# Importar módulos que generan alertas (deben existir en la carpeta)
import bruteforce
import login
import phishing
import ddos

app = Flask(__name__, static_url_path="", static_folder=".")

@app.route("/")
def index():
    # sirve index.html desde el directorio del proyecto
    return send_from_directory(".", "index.html")

@app.route("/health")
def health():
    return {"ok": True}, 200

def build_log_line(alerta_final: dict) -> str:
    """
    Formatea una línea corta para logs a partir de la alerta.
    Se asume que la alert dict contiene claves como fecha, hora, ip, usuario, intentos, duracion, login, etc.
    """
    fecha = alerta_final.get("fecha") or ""
    hora = alerta_final.get("hora") or ""
    ip = alerta_final.get("ip") or "-"
    usuario = alerta_final.get("usuario") or "-"
    intentos = alerta_final.get("intentos") or 0
    duracion = alerta_final.get("duracion") or 0
    login = (alerta_final.get("login") or "").lower()
    tag = "LOGIN_EXITO" if login in ("exito", "éxito", "success") else "LOGIN_FALLIDO"
    return f"[{fecha}] [{hora}] {tag} src_ip={{{ip}}} usuario={{{usuario}}} intentos={{{intentos}}} duracion={{{duracion}}}s"

@app.route("/random-alert", methods=["GET"])
def random_alert():
    """
    Endpoint que genera UNA alerta del tipo indicado por query param `type`.
    Parámetros aceptados (querystring):
      - type: bruteforce | login | phishing | dos | ddos   (default: bruteforce)
      - ip_source: any | bad | good                       (pasado a los generadores)
      - bad_prob: float (0..1)                            (pasado a los generadores)
      - with_enrichment / with_enrich: true|false        (si aplica)
    Retorna JSON con:
      {"ok": True, "alerta": { ... }, "log_line": "..."}
    """
    try:
        tipo = (request.args.get("type") or request.args.get("attack") or "bruteforce").lower()
        ip_source = (request.args.get("ip_source") or request.args.get("source") or "any").strip().lower()
        try:
            bad_prob = float(request.args.get("bad_prob") or request.args.get("badprob") or 0.5)
        except Exception:
            bad_prob = 0.5
        bad_prob = max(0.0, min(1.0, bad_prob))

        with_enrichment = (request.args.get("with_enrichment") or request.args.get("with_enrich") or "true")
        with_enrichment = str(with_enrichment).lower() in ("1", "true", "yes", "y")

        # Dispatch según tipo
        if tipo == "bruteforce":
            # bruteforce.generate_alert devuelve {"ok": True, "alerta": {...}, "saved": {...}}
            alerta_resp = bruteforce.generate_alert(ip_source=ip_source, bad_prob=bad_prob,
                                                    with_enrichment=with_enrichment, save_csv=True, save_db=True)
            alerta = alerta_resp.get("alerta") if isinstance(alerta_resp, dict) else alerta_resp
        elif tipo == "login":
            alerta = login.generate_alert(ip_source=ip_source, bad_prob=bad_prob,
                                          with_enrichment=with_enrichment, save_csv=True, save_db=True)
        elif tipo == "phishing":
            alerta = phishing.generate_alert(with_enrichment=with_enrichment, save_csv=True, save_db=True)
            # phishing.generate_alert returns a structure (alerta_para_ui or similar); keep as-is
        elif tipo == "dos":
            # DoS (tabla alertas_dos)
            alerta_resp = ddos.generate_dos_alert(ip_source=ip_source, bad_prob=bad_prob,
                                                  save_csv=True, save_db=True)
            alerta = alerta_resp.get("alerta") if isinstance(alerta_resp, dict) else alerta_resp
        elif tipo == "ddos":
            # DDoS (tabla alertas_ddos)
            alerta_resp = ddos.generate_ddos_alert(ip_source=ip_source, bad_prob=bad_prob,
                                                   save_csv=True, save_db=True)
            alerta = alerta_resp.get("alerta") if isinstance(alerta_resp, dict) else alerta_resp
        else:
            return jsonify({"ok": False, "error": "tipo desconocido", "type_received": tipo}), 400

        # Si alerta es None o malformada, devolver error
        if not alerta or not isinstance(alerta, dict):
            return jsonify({"ok": False, "error": "La generación de la alerta no devolvió datos válidos", "debug": str(alerta)}), 500

        # Construir línea de log simple
        log_line = build_log_line(alerta)

        # Responder con la alerta y línea de log
        return jsonify({"ok": True, "alerta": alerta, "log_line": log_line}), 200

    except Exception as e:
        # Devolver traza para depuración local (no recomendable en producción)
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500


if __name__ == "__main__":
    # Ejecuta la app en local
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", 5000)), debug=True)
