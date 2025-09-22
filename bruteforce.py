# bruteforce.py
import random
from datetime import datetime, timedelta

from bd import fetch_ip_malas, insert_alert_to_db
from save_csv import append_row_to_csv

def pick_ip(ip_source: str = "any", bad_prob: float = 0.5, conn_params=None):
    """
    ***REGLA ESTRICTA***: Todas las IPs se seleccionan EXCLUSIVAMENTE desde la BD (tabla ip_malas).
    - Se ignoran ip_source y bad_prob a efectos de generación (por compatibilidad con UI).
    - Si no hay IPs o hay error de conexión, se lanza excepción.
    """
    ips = fetch_ip_malas(conn_params=conn_params)
    return random.choice(ips)

def simular_bruteforce_alert(ip_source="any", bad_prob=0.5, conn_params=None):
    ip = pick_ip(ip_source=ip_source, bad_prob=bad_prob, conn_params=conn_params)
    ts = datetime.now() - timedelta(seconds=random.randint(0, 86400))
    # Generación mínima (usado internamente)
    return {
        "timestamp": ts.strftime('%Y-%m-%d %H:%M:%S'),
        "ip": ip,
        "intentos": random.randint(5, 40),
        "duracion": random.randint(1, 600)
    }

def generate_alert(ip_source="any", bad_prob=0.5, with_enrichment: bool = False, save_csv: bool = True, save_db: bool = True, conn_params=None):
    """
    Genera una alerta de fuerza bruta (tabla alertas_fuerza_bruta) según tus reglas:
      - target: 'ssh' o 'smb' al 50%
      - intentos: 100-1000 paso 100
      - ratio: 30-80 paso 10
    Guarda en CSV (reporte_alertas_fuerza_bruta.csv) y en BD (alertas_fuerza_bruta).
    """
    # IP desde BD
    ip = pick_ip(ip_source=ip_source, bad_prob=bad_prob, conn_params=conn_params)
    now = datetime.now()
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    target = random.choice(["ssh", "smb"])
    intentos = random.choice(list(range(100, 1001, 100)))  # 100..1000 step 100
    ratio = random.choice(list(range(30, 81, 10)))         # 30..80 step 10

    row_db = {
        "fecha": fecha,
        "hora": hora,
        "ip": ip,
        "target": target,
        "intentos": intentos,
        "ratio": ratio,
        "riesgo": None
    }

    # Guardar CSV
    if save_csv:
        append_row_to_csv(row_db, attack_type="bruteforce")

    # Guardar BD
    result_db = None
    if save_db:
        result_db = insert_alert_to_db(row_db, table_name="alertas_fuerza_bruta", conn_params=conn_params)

    # Respuesta para UI
    return {
        "ok": True,
        "alerta": row_db,
        "saved": {"csv": save_csv, "db": result_db}
    }
