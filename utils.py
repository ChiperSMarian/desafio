# utils.py
"""
Funciones de consulta a APIs, scoring y ensamblaje de alertas.

Incluye:
- consultas: VirusTotal (IP y dominios), AbuseIPDB, OTX, IPQualityScore (URL)
- funciones de scoring: score_from_virustotal, score_from_abuse, score_from_otx,
  score_phishing_url, score_login_ip
- crear_alerta_final utilizada por login/ddos/bruteforce
- import resiliente de cloudscraper (fallback a requests si no está disponible)
"""

import os
import json
import requests
from datetime import datetime
from typing import Tuple, Dict, Any, Optional

# intentamos cloudscraper pero aceptamos fallback a requests
try:
    import cloudscraper
    _HAS_CLOUDSCRAPER = True
except Exception:
    cloudscraper = None
    _HAS_CLOUDSCRAPER = False

# librerías auxiliares usadas para dominios y codificación
try:
    import tldextract
except Exception:
    tldextract = None

import urllib.parse
import math

# -------------------
# CONFIG (lee variables de entorno)
# -------------------
API_KEYS = {
    "virustotal": os.getenv("virustotal_api_key") or os.getenv("VIRUSTOTAL_API_KEY", ""),
    "abuseipdb": os.getenv("abuseipdb_api_key") or os.getenv("ABUSEIPDB_API_KEY", ""),
    "otx": os.getenv("otx_api_key") or os.getenv("OTX_API_KEY", ""),
    "urlscan": os.getenv("urlscan_api_key") or os.getenv("URLSCAN_API_KEY", ""),
    "ipqs": os.getenv("ipqualityscore") or os.getenv("IPQS_API_KEY", "")
}

# -------------------
# HTTP helper (usa cloudscraper si está, si no requests)
# -------------------
def _http_get(url: str, headers: Optional[dict] = None, params: Optional[dict] = None, timeout: int = 10):
    """
    GET robusto: intenta cloudscraper (para Cloudflare) y si falla usa requests.
    Devuelve objeto Response compatible (requests) o lanza excepción.
    """
    if _HAS_CLOUDSCRAPER and cloudscraper:
        try:
            s = cloudscraper.create_scraper()
            return s.get(url, headers=headers, params=params, timeout=timeout)
        except Exception:
            # caemos a requests
            pass
    return requests.get(url, headers=headers, params=params, timeout=timeout)

def consultar_api(url: str, headers: Optional[dict] = None, params: Optional[dict] = None, timeout: int = 10):
    """
    Wrapper que devuelve JSON o None / dict con keys __exception__/__status_code__ en caso de fallo.
    """
    try:
        r = _http_get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                return {"__status_code__": r.status_code, "__text__": r.text}
        else:
            return {"__status_code__": r.status_code, "__text__": r.text}
    except requests.exceptions.RequestException as e:
        return {"__exception__": str(e)}
    except Exception as e:
        return {"__exception__": str(e)}

# -------------------
# Consultas a APIs concretas
# -------------------
def consultar_virustotal_ip(ip_address: str):
    api_key = API_KEYS.get("virustotal") or ""
    if not api_key:
        return {"__error__": "No API key de VirusTotal configurada."}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    return consultar_api(url, headers=headers)

def consultar_abuseipdb_ip(ip_address: str):
    api_key = API_KEYS.get("abuseipdb") or ""
    if not api_key:
        return {"__error__": "No API key de AbuseIPDB configurada."}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 365}
    return consultar_api(url, headers=headers, params=params)

def consultar_otx_ip(ip_address: str):
    api_key = API_KEYS.get("otx") or ""
    if not api_key:
        return {"__error__": "No API key de OTX configurada."}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    headers = {"X-OTX-API-KEY": api_key}
    return consultar_api(url, headers=headers)

def consultar_virustotal_domain(hostname: str):
    """
    Consulta VirusTotal para un dominio (registered domain).
    Requiere tldextract; si no está, hace una llamada directa con hostname.
    """
    api_key = API_KEYS.get("virustotal") or ""
    if not api_key:
        return None
    dominio_raiz = None
    try:
        if tldextract:
            dominio_raiz = tldextract.extract(hostname).registered_domain
    except Exception:
        dominio_raiz = None
    dominio = dominio_raiz or hostname
    if not dominio:
        return None
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {"x-apikey": api_key}
    return consultar_api(url, headers=headers)

def consultar_ipqs_url(url: str):
    """
    Consulta IPQualityScore para URLs (requiere API key en API_KEYS['ipqs']).
    """
    api_key = API_KEYS.get("ipqs") or ""
    if not api_key:
        return None
    url_codificada = urllib.parse.quote_plus(url)
    endpoint = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{url_codificada}"
    return consultar_api(endpoint)

# -------------------
# Scoring (varias heurísticas)
# -------------------
def score_from_virustotal(vt_json):
    try:
        if not vt_json or not isinstance(vt_json, dict) or 'data' not in vt_json:
            return 0.0
        stats = vt_json.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = int(stats.get('malicious', 0) or 0)
        suspicious = int(stats.get('suspicious', 0) or 0)
        # heurística: (malicious*5 + suspicious)/some -> to 0..10
        score = min((malicious * 5) + suspicious, 10)
        return float(score)
    except Exception:
        return 0.0

def score_from_abuse(abuse_json):
    try:
        if not abuse_json or not isinstance(abuse_json, dict):
            return 0.0
        data = abuse_json.get("data") or abuse_json
        score100 = data.get("abuseConfidenceScore", 0)
        return float(score100) / 10.0
    except Exception:
        return 0.0

def score_from_otx(otx_json):
    try:
        if not otx_json or not isinstance(otx_json, dict):
            return 0.0
        if "pulse_info" in otx_json:
            pulses = (otx_json.get("pulse_info") or {}).get("count", 0) or 0
            # map pulses to 0..10 (log scale)
            if pulses <= 0:
                return 0.0
            return min(10.0, math.log10(pulses + 1) * 3.3)
        rep = otx_json.get("reputation")
        if rep is not None:
            return min(10.0, float(rep) / 10.0)
        return 0.0
    except Exception:
        return 0.0

def score_phishing_url(vt_json, ipqs_json):
    """
    Scoring simple para URLs: combina VT (dominio) e IPQS (url) 50/50 y devuelve 0..10 float.
    """
    score_vt = score_from_virustotal(vt_json)
    score_ipqs = 0.0
    try:
        if ipqs_json and isinstance(ipqs_json, dict) and ipqs_json.get("success"):
            # ipqs risk_score normalmente 0..100 -> normalizamos a 0..10
            score_ipqs = float(ipqs_json.get("risk_score", 0)) / 10.0
    except Exception:
        score_ipqs = 0.0
    score_final = (score_vt * 0.5) + (score_ipqs * 0.5)
    return min(10.0, round(score_final, 2))

def score_login_ip(vt_json, abuse_json, otx_json):
    """
    Combina los tres scores con pesos y renormaliza si uno o más faltan.
    """
    score_vt = score_from_virustotal(vt_json)
    score_abuse = score_from_abuse(abuse_json)
    score_otx = score_from_otx(otx_json)
    base_weights = {"vt": 0.60, "abuse": 0.30, "otx": 0.10}
    scores = {"vt": score_vt, "abuse": score_abuse, "otx": score_otx}
    active = {k: v for k, v in scores.items() if v and v > 0}
    if not active:
        return 0.0
    total_w = sum(base_weights[k] for k in active.keys())
    weighted = sum((base_weights[k] * active[k]) for k in active.keys())
    score_final = weighted / total_w
    return min(10.0, round(score_final, 2))

# -------------------
# Clasificación final genérica
# -------------------
def clasificar_por_score_final(score_final: float) -> str:
    if score_final <= 0:
        return "Inofensivo"
    elif score_final <= 3.9:
        return "Bajo"
    elif score_final <= 6.9:
        return "Medio"
    elif score_final <= 8.9:
        return "Alto"
    else:
        return "Crítico"

# -------------------
# Crear alerta final (compatible con login/ddos/bruteforce code)
# -------------------
def crear_alerta_final(alerta_base: Dict[str, Any], vt_json=None, abuse_json=None, otx_json=None) -> Dict[str, Any]:
    """
    Construye la alerta final a partir de una alerta_base con 'timestamp','usuario','intentos','duracion','ip','login' etc.
    Calcula scores y risk_level.
    """
    # timestamp esperado: 'YYYY-MM-DD HH:MM:SS' en alerta_base["timestamp"]
    try:
        fecha, hora = alerta_base.get("timestamp", "").split(" ")
    except Exception:
        now = datetime.now()
        fecha = now.strftime("%Y-%m-%d")
        hora = now.strftime("%H:%M:%S")

    score_vt = score_from_virustotal(vt_json)
    score_abuse = score_from_abuse(abuse_json)
    score_otx = score_from_otx(otx_json)

    score_final, riesgo = (0.0, "Inofensivo")
    try:
        # si todos 0 => score_final 0 (inofensivo/desconocido)
        if score_vt == 0 and score_abuse == 0 and score_otx == 0:
            score_final = 0.0
            riesgo = "Desconocido"
        else:
            score_final = score_login_ip(vt_json, abuse_json, otx_json)
            riesgo = clasificar_por_score_final(score_final)
    except Exception:
        score_final = 0.0
        riesgo = "Desconocido"

    # inferir pais/isp minimal desde VT si existe
    pais = (vt_json or {}).get("data", {}).get("attributes", {}).get("country") if isinstance(vt_json, dict) else None
    isp = (vt_json or {}).get("data", {}).get("attributes", {}).get("as_owner") if isinstance(vt_json, dict) else None

    # calcular ratio_intentos si podemos
    try:
        intentos = int(alerta_base.get("intentos") or 0)
        dur = int(alerta_base.get("duracion") or 0) or 1
        ratio_intentos = round(intentos / dur, 6) if dur > 0 else None
    except Exception:
        ratio_intentos = None

    alerta_final = {
        "fecha": fecha,
        "hora": hora,
        "usuario": alerta_base.get("usuario"),
        "intentos": int(alerta_base.get("intentos") or 0) if alerta_base.get("intentos") is not None else None,
        "duracion": int(alerta_base.get("duracion") or 0) if alerta_base.get("duracion") is not None else None,
        "ratio_intentos": ratio_intentos,
        "ip": alerta_base.get("ip"),
        "login": alerta_base.get("login"),
        "pais": pais,
        "isp": isp,
        "uso": alerta_base.get("uso"),
        "resultado_vt_raw": json.dumps((vt_json or {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}), ensure_ascii=False) if isinstance(vt_json, dict) else None,
        "score_vt": round(float(score_vt or 0.0), 2),
        "score_abuse": round(float(score_abuse or 0.0), 2),
        "score_otx": round(float(score_otx or 0.0), 2),
        "score_final": round(float(score_final or 0.0), 2),
        "risk_level": riesgo
    }

    return alerta_final

# -------------------
# Export
# -------------------
__all__ = [
    "consultar_api", "consultar_virustotal_ip", "consultar_abuseipdb_ip", "consultar_otx_ip",
    "consultar_virustotal_domain", "consultar_ipqs_url",
    "score_from_virustotal", "score_from_abuse", "score_from_otx",
    "score_phishing_url", "score_login_ip",
    "crear_alerta_final", "clasificar_por_score_final"
]
