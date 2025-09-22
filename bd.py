# bd.py
import os
import psycopg2
from pathlib import Path

# Para los CSVs
try:
    from save_csv import append_row_to_csv
except Exception:
    # fallback si no existe save_csv para que no rompa imports
    def append_row_to_csv(row, csv_file=None, attack_type=None, encoding='utf-8'):
        return {"ok": False, "error": "save_csv no disponible"}

# =====================
# Parámetros de conexión
# =====================
DB_USER = os.getenv("db_user")
DB_PASSWORD = os.getenv("db_password")
DB_HOST = os.getenv("db_host")
DB_PORT = os.getenv("db_port")
DB_NAME = os.getenv("db_name")

DEFAULT_CSV = os.getenv("DEFAULT_CSV", "reporte_alertas.csv")

def get_conn_params():
    params = {
        "user": DB_USER,
        "password": DB_PASSWORD,
        "host": DB_HOST,
        "port": DB_PORT,
        "dbname": DB_NAME,
        "connect_timeout": int(os.getenv("db_connect_timeout", "5")),
    }
    sslmode = os.getenv("db_sslmode")
    if sslmode:
        params["sslmode"] = sslmode
    return params

def _connect(conn_params=None):
    if conn_params is None:
        conn_params = get_conn_params()
    return psycopg2.connect(**conn_params)

# =====================
# Lectura tablas 'malas'
# =====================
def fetch_ip_malas(conn_params=None) -> list:
    """
    Devuelve la lista de IPs almacenadas en la tabla `ip_malas`.
    Lanza RuntimeError si la tabla no existe o está vacía.
    """
    if conn_params is None:
        conn_params = get_conn_params()
    conn = None
    try:
        conn = psycopg2.connect(**conn_params)
        with conn.cursor() as cur:
            cur.execute("SELECT ip FROM ip_malas;")
            rows = cur.fetchall()
            ips = [r[0] for r in rows if r and r[0]]
        if not ips:
            raise RuntimeError("La tabla 'ip_malas' está vacía. Inserta IPs antes de generar alertas.")
        return ips
    except psycopg2.Error as e:
        raise RuntimeError(f"Error al leer 'ip_malas' en la BBDD: {e}")
    finally:
        if conn:
            conn.close()

def fetch_url_malas(conn_params=None) -> list:
    """
    Devuelve la lista de URLs almacenadas en la tabla `url_malas`.
    Lanza RuntimeError si la tabla no existe o está vacía.
    """
    if conn_params is None:
        conn_params = get_conn_params()
    conn = None
    try:
        conn = psycopg2.connect(**conn_params)
        with conn.cursor() as cur:
            # Asume columna 'url' en la tabla url_malas
            cur.execute("SELECT url FROM url_malas;")
            rows = cur.fetchall()
            urls = [r[0] for r in rows if r and r[0]]
        if not urls:
            raise RuntimeError("La tabla 'url_malas' está vacía. Inserta URLs antes de generar alertas.")
        return urls
    except psycopg2.Error as e:
        raise RuntimeError(f"Error al leer 'url_malas' en la BBDD: {e}")
    finally:
        if conn:
            conn.close()

# =====================
# Crear tablas (si no existen)
# =====================
def ensure_db_table(conn, table_name: str):
    """
    Crea tablas necesarias si no existen. Mantiene orden de columnas tal y como pediste.
    """
    if not table_name:
        raise ValueError("table_name requerido")

    # Tablas solicitadas en la conversación
    if table_name == "alertas_fuerza_bruta":
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY,
            fecha DATE,
            hora TIME,
            ip TEXT,
            target TEXT,
            intentos INTEGER,
            ratio NUMERIC,
            riesgo TEXT
        );
        """
    elif table_name == "alertas_dos":
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY,
            fecha DATE,
            hora TIME,
            ip TEXT,
            requests INTEGER,
            ratio NUMERIC,
            riesgo TEXT
        );
        """
    elif table_name == "alertas_ddos":
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY,
            fecha DATE,
            hora TIME,
            ip TEXT,
            sources INTEGER,
            requests INTEGER,
            ratio NUMERIC,
            riesgo TEXT
        );
        """
    # Tablas ya usadas por otras partes del proyecto (compatibilidad)
    elif table_name == "alertas_login_sospechoso":
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY,
            fecha DATE,
            hora TIME,
            usuario TEXT,
            intentos INTEGER,
            duracion INTEGER,
            ratio_intentos NUMERIC,
            ip TEXT,
            login TEXT,
            pais TEXT,
            isp TEXT,
            uso TEXT,
            resultado_vt_raw TEXT,
            score_vt NUMERIC,
            score_abuse NUMERIC,
            score_otx NUMERIC,
            score_final NUMERIC,
            risk_level TEXT
        );
        """
    elif table_name == "alertas_phishing":
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY,
            url TEXT,
            risk_level TEXT,
            resultado TEXT
        );
        """
    else:
        # tabla por defecto (compatibilidad)
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY,
            fecha DATE,
            hora TIME,
            intentos INTEGER,
            duracion INTEGER,
            ratio_intentos NUMERIC,
            ip TEXT,
            pais TEXT,
            score_final NUMERIC,
            risk_level TEXT
        );
        """

    with conn.cursor() as cur:
        cur.execute(create_table_sql)
        conn.commit()

# =====================
# Insert genérico (con CSV opcional)
# =====================
def insert_alert_to_db(row_dict, table_name: str = "alertas_login_sospechoso", conn_params=None, write_csv: bool = True):
    """
    Inserta una fila en la tabla indicada. Opcionalmente añade la fila al CSV de reporte
    correspondiente (reporte_alertas_<tipo>.csv) usando save_csv.append_row_to_csv.
    Devuelve {"ok": True, "id": new_id} o {"ok": False, "error": "..."}
    """
    if conn_params is None:
        conn_params = get_conn_params()

    conn = None
    try:
        conn = psycopg2.connect(**conn_params)
        ensure_db_table(conn, table_name)

        if table_name == "alertas_fuerza_bruta":
            insert_sql = f"""
            INSERT INTO {table_name}
            (fecha, hora, ip, target, intentos, ratio, riesgo)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """
            params = (
                row_dict.get("fecha"),
                row_dict.get("hora"),
                row_dict.get("ip"),
                row_dict.get("target"),
                int(row_dict.get("intentos") or 0),
                float(row_dict.get("ratio") or 0.0),
                row_dict.get("riesgo")
            )
        elif table_name == "alertas_dos":
            insert_sql = f"""
            INSERT INTO {table_name}
            (fecha, hora, ip, requests, ratio, riesgo)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id;
            """
            params = (
                row_dict.get("fecha"),
                row_dict.get("hora"),
                row_dict.get("ip"),
                int(row_dict.get("requests") or 0),
                float(row_dict.get("ratio") or 0.0),
                row_dict.get("riesgo")
            )
        elif table_name == "alertas_ddos":
            insert_sql = f"""
            INSERT INTO {table_name}
            (fecha, hora, ip, sources, requests, ratio, riesgo)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """
            params = (
                row_dict.get("fecha"),
                row_dict.get("hora"),
                row_dict.get("ip"),
                int(row_dict.get("sources") or 0),
                int(row_dict.get("requests") or 0),
                float(row_dict.get("ratio") or 0.0),
                row_dict.get("riesgo")
            )
        elif table_name == "alertas_login_sospechoso":
            insert_sql = f"""
            INSERT INTO {table_name}
            (fecha, hora, usuario, intentos, duracion, ratio_intentos, ip, login, pais, isp, uso, resultado_vt_raw,
             score_vt, score_abuse, score_otx, score_final, risk_level)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """
            params = (
                row_dict.get("fecha"),
                row_dict.get("hora"),
                row_dict.get("usuario"),
                int(row_dict.get("intentos") or 0),
                int(row_dict.get("duracion") or 0),
                float(row_dict.get("ratio_intentos") or 0.0),
                row_dict.get("ip"),
                row_dict.get("login"),
                row_dict.get("pais"),
                row_dict.get("isp"),
                row_dict.get("uso"),
                row_dict.get("resultado_vt_raw"),
                float(row_dict.get("score_vt") or 0.0),
                float(row_dict.get("score_abuse") or 0.0),
                float(row_dict.get("score_otx") or 0.0),
                float(row_dict.get("score_final") or 0.0),
                row_dict.get("risk_level"),
            )
        elif table_name == "alertas_phishing":
            insert_sql = f"""
            INSERT INTO {table_name}
            (url, risk_level, resultado)
            VALUES (%s, %s, %s)
            RETURNING id;
            """
            params = (
                row_dict.get("url"),
                row_dict.get("risk_level"),
                row_dict.get("resultado") or row_dict.get("resultado_vt_raw") or None,
            )
        else:
            # inserción por defecto (compatibilidad)
            insert_sql = f"""
            INSERT INTO {table_name}
            (fecha, hora, intentos, duracion, ratio_intentos, ip, pais, score_final, risk_level)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """
            params = (
                row_dict.get("fecha"),
                row_dict.get("hora"),
                int(row_dict.get("intentos") or 0),
                int(row_dict.get("duracion") or 0),
                float(row_dict.get("ratio_intentos") or 0.0),
                row_dict.get("ip"),
                row_dict.get("pais"),
                float(row_dict.get("score_final") or 0.0),
                row_dict.get("risk_level"),
            )

        with conn.cursor() as cur:
            cur.execute(insert_sql, params)
            new_id = cur.fetchone()[0]
            conn.commit()

        # Escritura CSV opcional (nombre por tipo)
        if write_csv:
            table_to_attack = {
                "alertas_fuerza_bruta": "bruteforce",
                "alertas_dos": "dos",
                "alertas_ddos": "ddos",
                "alertas_login_sospechoso": "login",
                "alertas_phishing": "phishing"
            }
            atk = table_to_attack.get(table_name, table_name.replace("alertas_", ""))
            try:
                append_row_to_csv(row_dict, attack_type=atk)
            except Exception:
                # no rompemos la inserción por un error en CSV
                print("Advertencia: fallo al escribir CSV para", table_name)

        return {"ok": True, "id": new_id}

    except Exception as e:
        if conn:
            conn.rollback()
        return {"ok": False, "error": str(e)}
    finally:
        if conn:
            conn.close()
