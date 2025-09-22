# login.py
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import random
from datetime import datetime, timedelta
from typing import Dict, Any

from utils import consultar_virustotal_ip, consultar_abuseipdb_ip, consultar_otx_ip, crear_alerta_final
from bd import insert_alert_to_db
from save_csv import append_row_to_csv

# Reutilizamos pick_ip de bruteforce para consistencia
from bruteforce import pick_ip

def simular_alerta_base(ip_source: str = "any", bad_prob: float = 0.5) -> Dict[str, Any]:
    ip = pick_ip(ip_source=ip_source, bad_prob=bad_prob)
    resultado_login = random.choices(["Fallido", "Exito"], weights=[80, 20], k=1)[0]
    segundos_aleatorios = random.randint(0, 86400)
    timestamp_aleatorio = datetime.now() - timedelta(seconds=segundos_aleatorios)
    usuarios = ['admin', 'root', 'user', 'guest', f"user{random.randint(1,999)}"]
    return {
        "timestamp": timestamp_aleatorio.strftime('%Y-%m-%d %H:%M:%S'),
        "usuario": random.choice(usuarios),
        "intentos": int(random.randint(1, 30)),
        "duracion": int(random.randint(5, 600)),
        "ip": ip,
        "login": resultado_login
    }

def generate_alert(ip_source: str = "any", bad_prob: float = 0.5,
                   with_enrichment: bool = True, save_csv: bool = True, save_db: bool = True) -> Dict[str, Any]:
    """
    Genera una alerta tipo 'login', la enriquece, calcula score,
    guarda en CSV específico y en la tabla 'alertas_login_sospechoso' si save_db=True.
    """
    alerta_base = simular_alerta_base(ip_source=ip_source, bad_prob=bad_prob)

    vt_json = abuse_json = otx_json = None
    if with_enrichment:
        vt_json = consultar_virustotal_ip(alerta_base["ip"])
        abuse_json = consultar_abuseipdb_ip(alerta_base["ip"])
        otx_json = consultar_otx_ip(alerta_base["ip"])

    alerta_final = crear_alerta_final(alerta_base, vt_json, abuse_json, otx_json)

    if save_csv:
        append_row_to_csv(alerta_final, attack_type="login")

    if save_db:
        insert_alert_to_db(alerta_final, table_name="alertas_login_sospechoso")

    return alerta_final
