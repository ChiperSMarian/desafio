# ddos.py
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import random
from datetime import datetime
from typing import Dict, Any, Optional

from bd import insert_alert_to_db, fetch_ip_malas
from save_csv import append_row_to_csv

# --- helper para elegir IP desde la tabla ip_malas ---
def pick_ip_from_db(conn_params: Optional[dict] = None) -> str:
    """
    Lee la tabla ip_malas desde bd.fetch_ip_malas si existe.
    Mantengo aquí una llamada directa a bd.fetch_ip_malas para compatibilidad.
    """
    try:
        # import aquí para evitar ciclos al importar módulos desde app
        from bd import fetch_ip_malas as _fetch
        ips = _fetch(conn_params=conn_params)
        if not ips:
            raise RuntimeError("No hay IPs en la tabla 'ip_malas'.")
        return random.choice(ips)
    except Exception as e:
        raise

# ---------- Generador DoS (tabla alertas_dos) ----------
def generate_dos_alert(ip_source: str = "any", bad_prob: float = 0.5,
                       save_csv: bool = True, save_db: bool = True, conn_params: Optional[dict] = None) -> Dict[str, Any]:
    """
    Genera una alerta 'dos' y la guarda en 'alertas_dos'
      - requests: 1000-5000 step 1000
      - ratio: 100-1000 step 100
    """
    # IP desde BD (si falla, lanzará excepción)
    ip = pick_ip_from_db(conn_params=conn_params)
    now = datetime.now()
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    requests_count = random.choice(list(range(1000, 5001, 1000)))  # 1000..5000 step 1000
    ratio = random.choice(list(range(100, 1001, 100)))            # 100..1000 step 100

    row_db = {
        "fecha": fecha,
        "hora": hora,
        "ip": ip,
        "requests": requests_count,
        "ratio": ratio,
        "riesgo": None
    }

    if save_csv:
        append_row_to_csv(row_db, attack_type="ddos")  # uso csv ddos para ambos DoS/DDoS por claridad

    result_db = None
    if save_db:
        result_db = insert_alert_to_db(row_db, table_name="alertas_dos", conn_params=conn_params)

    return {"ok": True, "alerta": row_db, "saved": {"csv": save_csv, "db": result_db}}

# ---------- Generador DDoS (tabla alertas_ddos) ----------
def generate_ddos_alert(ip_source: str = "any", bad_prob: float = 0.5,
                        save_csv: bool = True, save_db: bool = True, conn_params: Optional[dict] = None) -> Dict[str, Any]:
    """
    Genera una alerta 'ddos' y la guarda en 'alertas_ddos'
      - sources: 300-1500 step 100
      - requests: 10000-100000 step 5000
      - ratio: 500-5000 step 100
    """
    ip = pick_ip_from_db(conn_params=conn_params)
    now = datetime.now()
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    sources = random.choice(list(range(300, 1501, 100)))            # 300..1500 step 100
    requests_count = random.choice(list(range(10_000, 100_001, 5_000)))  # 10k..100k step 5k
    ratio = random.choice(list(range(500, 5_001, 100)))             # 500..5000 step 100

    row_db = {
        "fecha": fecha,
        "hora": hora,
        "ip": ip,
        "sources": sources,
        "requests": requests_count,
        "ratio": ratio,
        "riesgo": None
    }

    if save_csv:
        append_row_to_csv(row_db, attack_type="ddos")

    result_db = None
    if save_db:
        result_db = insert_alert_to_db(row_db, table_name="alertas_ddos", conn_params=conn_params)

    return {"ok": True, "alerta": row_db, "saved": {"csv": save_csv, "db": result_db}}

# ---------- Dispatcher por compatibilidad (si se llama generically) ----------
def generate_alert(ip_source: str = "any", bad_prob: float = 0.5,
                   with_enrichment: bool = True, save_csv: bool = True, save_db: bool = True,
                   conn_params: Optional[dict] = None, attack: str = "ddos") -> Dict[str, Any]:
    """
    Dispatcher backward-compatible: si attack == 'dos' genera doS; si 'ddos' genera ddos.
    """
    a = (attack or "ddos").lower()
    if a == "dos":
        return generate_dos_alert(ip_source=ip_source, bad_prob=bad_prob, save_csv=save_csv, save_db=save_db, conn_params=conn_params)
    else:
        return generate_ddos_alert(ip_source=ip_source, bad_prob=bad_prob, save_csv=save_csv, save_db=save_db, conn_params=conn_params)
