# phishing.py
"""
Generador de alertas de phishing. Usa:
 - fetch_url_malas() desde bd.py para elegir URL objetivo
 - consultar_virustotal_domain() y consultar_ipqs_url() desde utils.py para enriquecimiento
 - score_phishing_url() para puntuar la URL
 - insert_alert_to_db() para guardar en alertas_phishing
 - append_row_to_csv() para generar CSV de reporte por tipo
"""

import os
import sys
import random
from typing import Dict, Any
from urllib.parse import urlparse
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils import (consultar_virustotal_domain, consultar_ipqs_url, score_phishing_url)
from bd import insert_alert_to_db, fetch_url_malas
from save_csv import append_row_to_csv

def simular_alerta_base(conn_params=None) -> Dict[str, Any]:
    """
    Selecciona aleatoriamente una URL desde la tabla url_malas.
    Lanza excepción si la tabla está vacía (fetch_url_malas lo controla).
    """
    urls = fetch_url_malas(conn_params=conn_params)
    return {"url": random.choice(urls)}

def generate_alert(with_enrichment: bool = True, save_csv: bool = True, save_db: bool = True, conn_params=None) -> Dict[str, Any]:
    """
    Orquesta la generación completa de una alerta de phishing.
    Devuelve un dict listo para UI (fecha,hora,url,ip,pais,isp,score_final,risk_level,resultado)
    """
    alerta_base = simular_alerta_base(conn_params=conn_params)
    url_a_analizar = alerta_base["url"]
    hostname = urlparse(url_a_analizar).hostname or url_a_analizar

    vt_json = None
    ipqs_json = None

    if with_enrichment:
        # llamadas defensivas: si no hay API key o la consulta falla, las funciones devuelven None o dict con error
        try:
            vt_json = consultar_virustotal_domain(hostname)
        except Exception:
            vt_json = None
        try:
            ipqs_json = consultar_ipqs_url(url_a_analizar)
        except Exception:
            ipqs_json = None

    # scoring: score_phishing_url devuelve float 0..10
    score_final = score_phishing_url(vt_json, ipqs_json)

    # mapear a etiquetas de riesgo para BD/UI (misma heurística que usaba phishing2)
    if score_final >= 9.0:
        riesgo = "Crítico"
    elif score_final >= 7.0:
        riesgo = "Alto"
    elif score_final >= 4.0:
        riesgo = "Medio"
    elif score_final > 0:
        riesgo = "Bajo"
    else:
        riesgo = "Inofensivo"

    # construir campo 'resultado' con un resumen corto de VT/IPQS
    try:
        vt_malicious = "N/A"
        if isinstance(vt_json, dict) and "data" in vt_json:
            vt_malicious = vt_json["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", "N/A")
    except Exception:
        vt_malicious = "N/A"

    try:
        ipqs_score = ipqs_json.get("risk_score", "N/A") if isinstance(ipqs_json, dict) else "N/A"
    except Exception:
        ipqs_score = "N/A"

    resultado_str = f"VT: M{vt_malicious}, IPQS: S{ipqs_score}"

    # alerta para UI
    now = datetime.now()
    alerta_ui = {
        "fecha": now.strftime('%Y-%m-%d'),
        "hora": now.strftime('%H:%M:%S'),
        "usuario": "N/A",
        "intentos": "N/A",
        "duracion": "N/A",
        "ratio_intentos": "N/A",
        "ip": hostname,
        "url": url_a_analizar,
        "login": "N/A",
        "pais": (vt_json or {}).get("data", {}).get("attributes", {}).get("country", "N/A") if isinstance(vt_json, dict) else "N/A",
        "isp": (vt_json or {}).get("data", {}).get("attributes", {}).get("as_owner", "N/A") if isinstance(vt_json, dict) else "N/A",
        "uso": "Phishing",
        "score_final": score_final,
        "risk_level": riesgo,
        "resultado": resultado_str
    }

    # Escritura CSV (archivo por tipo) y BD (tabla alertas_phishing)
    if save_csv:
        try:
            append_row_to_csv(alerta_ui, attack_type="phishing")
        except Exception:
            # no romper la generación por fallo en CSV
            pass

    if save_db:
        try:
            alerta_para_db = {"url": url_a_analizar, "risk_level": riesgo, "resultado": resultado_str}
            insert_alert_to_db(alerta_para_db, table_name="alertas_phishing", conn_params=conn_params)
        except Exception:
            # no romper la generación por fallo BD; la función insert_alert_to_db devuelve dict con ok/err si la usas directamente
            pass

    return alerta_ui
