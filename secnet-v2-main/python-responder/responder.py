#!/usr/bin/env python3
import json
import os
import time
import sqlite3
import logging
import subprocess
import ipaddress
from datetime import datetime
from threading import Thread
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, request, jsonify
import re

# ----------------------------------------
# Configuración de logging
# ----------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('responder.log')
    ]
)
logger = logging.getLogger('responder')

# ----------------------------------------
# Rutas y esquemas de base de datos
# ----------------------------------------
DB_PATH = './database/alerts.db'

def init_database():
    """Inicializa la base de datos SQLite si no existe."""
    db_dir = os.path.dirname(DB_PATH)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL;')
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        alert_message TEXT,
        severity INTEGER,
        protocol TEXT,
        action_taken TEXT,
        raw_data TEXT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE,
        timestamp TEXT,
        reason TEXT
    )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Base de datos inicializada en %s", DB_PATH)

# ----------------------------------------
# Función para validar IP
# ----------------------------------------
def validate_ip(ip_address):
    """Valida que la cadena sea una IPv4 o IPv6 válida."""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

# ----------------------------------------
# Funciones de bloqueo/desbloqueo de IP
# ----------------------------------------
def block_ip(ip_address, reason):
    """Bloquea una IP usando iptables y la registra en la BD."""
    try:
        if not validate_ip(ip_address):
            logger.error("IP inválida: %s", ip_address)
            return False
        
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute('PRAGMA journal_mode=WAL;')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocked_ips WHERE ip_address = ?", (ip_address,))
        if cursor.fetchone():
            logger.info("IP %s ya está bloqueada (registro encontrado)", ip_address)
            conn.close()
            return False
        
        timestamp = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO blocked_ips (ip_address, timestamp, reason) VALUES (?, ?, ?)",
            (ip_address, timestamp, reason)
        )
        conn.commit()
        conn.close()
        
        try:
            # Verificar si ya existe la regla en INPUT
            check_cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                # Añadir regla en INPUT
                block_cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
                subprocess.run(block_cmd, check=True)
                # Añadir regla en OUTPUT
                block_output_cmd = ["iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"]
                subprocess.run(block_output_cmd, check=True)
                # Guardar reglas persistentes
                save_cmd = ["netfilter-persistent", "save"]
                subprocess.run(save_cmd, check=True)
                logger.info("IP %s bloqueada correctamente", ip_address)
                return True
            else:
                logger.info("IP %s ya estaba bloqueada en iptables", ip_address)
                return True
        except subprocess.CalledProcessError as e:
            logger.error("Error al ejecutar iptables: %s", e)
            # Intentar con sudo
            try:
                sudo_block_cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
                subprocess.run(sudo_block_cmd, check=True)
                sudo_block_output_cmd = ["sudo", "iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"]
                subprocess.run(sudo_block_output_cmd, check=True)
                sudo_save_cmd = ["sudo", "netfilter-persistent", "save"]
                subprocess.run(sudo_save_cmd, check=True)
                logger.info("IP %s bloqueada correctamente con sudo", ip_address)
                return True
            except subprocess.CalledProcessError as e2:
                logger.error("Error al ejecutar iptables con sudo: %s", e2)
                return False
    except Exception as e:
        logger.error("Error en block_ip(): %s", e)
        return False

def unblock_ip(ip_address):
    """Desbloquea una IP de iptables y la elimina de la BD."""
    try:
        try:
            # Eliminar regla INPUT
            unblock_input_cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(unblock_input_cmd, check=True)
            # Eliminar regla OUTPUT
            unblock_output_cmd = ["iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"]
            subprocess.run(unblock_output_cmd, check=True)
            # Guardar cambios
            save_cmd = ["netfilter-persistent", "save"]
            subprocess.run(save_cmd, check=True)
            # Eliminar de la base de datos
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
            conn.commit()
            conn.close()
            logger.info("IP %s desbloqueada correctamente", ip_address)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Error al ejecutar iptables: %s", e)
            # Intentar con sudo
            try:
                sudo_unblock_input_cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
                subprocess.run(sudo_unblock_input_cmd, check=True)
                sudo_unblock_output_cmd = ["sudo", "iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"]
                subprocess.run(sudo_unblock_output_cmd, check=True)
                sudo_save_cmd = ["sudo", "netfilter-persistent", "save"]
                subprocess.run(sudo_save_cmd, check=True)
                # Eliminar de la base de datos
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
                conn.commit()
                conn.close()
                logger.info("IP %s desbloqueada correctamente con sudo", ip_address)
                return True
            except subprocess.CalledProcessError as e2:
                logger.error("Error al ejecutar iptables con sudo: %s", e2)
                return False
    except Exception as e:
        logger.error("Error en unblock_ip(): %s", e)
        return False

# ----------------------------------------
# Listas de IPs y dominios de confianza
# ----------------------------------------
LOCAL_IPS = {'127.0.0.1', '10.0.2.15', '::1', 'localhost'}
SAFE_DOMAINS = [
    r'.*\.codeium\.com$', r'.*githubusercontent\.com$', r'.*docker\.io$',
    r'codeium\.com$', r'githubusercontent\.com$', r'docker\.io$',
    r'example\.lan$', r'localdomain$', r'local$'
]
SAFE_IPS = {'8.8.8.8', '1.1.1.1'}

# ----------------------------------------
# Clasificación de alertas
# ----------------------------------------
def classify_alert(alert_data):
    src_ip = alert_data.get('src_ip', '')
    dest_ip = alert_data.get('dest_ip', '')
    dns_rrname = ''
    if 'dns' in alert_data and 'rrname' in alert_data['dns']:
        dns_rrname = alert_data['dns']['rrname']
    alert_msg = alert_data.get('alert', {}).get('signature', '')
    priority = int(alert_data.get('alert', {}).get('priority', 3))  # Por defecto baja
    
    # Mapeo de prioridad de Suricata a severidad
    # priority 1 = severidad 3 (alta)
    # priority 2 = severidad 2 (media)
    # priority 3 = severidad 1 (baja)
    severity = 4 - priority
    
    # --- HTTP interno: siempre severidad 1 ---
    if 'http' in alert_msg.lower():
        if ((src_ip in LOCAL_IPS or src_ip in SAFE_IPS) and
            (dest_ip in LOCAL_IPS or dest_ip in SAFE_IPS)):
            return 'HTTP interno bajo', 1
        for pattern in SAFE_DOMAINS:
            if (dns_rrname and re.search(pattern, dns_rrname)) or re.search(pattern, dest_ip):
                return 'HTTP interno bajo', 1
    
    # --- Tráfico interno seguro (no HTTP): ignorar ---
    if ((src_ip in LOCAL_IPS or src_ip in SAFE_IPS) and
        (dest_ip in LOCAL_IPS or dest_ip in SAFE_IPS)):
        return 'Tráfico interno seguro', 0
    
    for pattern in SAFE_DOMAINS:
        if (dns_rrname and re.search(pattern, dns_rrname)) or re.search(pattern, dest_ip):
            return 'Tráfico legítimo externo', 1
    if src_ip in SAFE_IPS:
        return 'Tráfico legítimo externo', 1
        
    # --- Clasificar según severidad ---
    if severity == 3:
        return 'Amenaza confirmada', severity
    elif severity == 2:
        return 'Actividad sospechosa', severity
    else:
        return 'Actividad normal', severity

def process_alert(alert_data):
    """Procesa una alerta de Suricata y toma las acciones necesarias."""
    try:
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        src_ip = alert_data.get('src_ip', 'unknown')
        dest_ip = alert_data.get('dest_ip', 'unknown')
        
        # Extraer puerto de destino si está presente
        dest_port = None
        if 'dest_port' in alert_data and alert_data['dest_port']:
            try:
                dest_port = int(alert_data['dest_port'])
            except (ValueError, TypeError):
                dest_port = None
        elif ':' in str(dest_ip):
            parts = str(dest_ip).split(':')
            if len(parts) > 1:
                dest_ip = parts[0]
                try:
                    dest_port = int(parts[1])
                except (ValueError, IndexError):
                    dest_port = None
        
        alert_message = alert_data.get('alert', {}).get('signature', 'Unknown alert')
        protocol = alert_data.get('proto', 'unknown')
        categoria, nueva_severidad = classify_alert(alert_data)
        
        # Determinar acción según categoría/severidad
        if categoria == 'HTTP interno bajo':
            severity = 1
            action_taken = "Tráfico HTTP interno registrado"
        elif categoria == 'Tráfico interno seguro':
            logger.info("Ignorado: %s de %s a %s (tráfico interno seguro)", alert_message, src_ip, dest_ip)
            return
        elif categoria == 'Tráfico legítimo externo':
            severity = 1
            action_taken = "Tráfico legítimo externo registrado"
        else:
            severity = nueva_severidad
            action_taken = "Logged only"
            
            # Bloquear IPs maliciosas
            if ((categoria == 'Amenaza confirmada') or
                (categoria == 'Actividad sospechosa' and severity >= 2)) and \
               (src_ip not in LOCAL_IPS and src_ip not in SAFE_IPS):
                if block_ip(src_ip, f"{alert_message} [{categoria}]"):
                    action_taken = f"Blocked source IP: {src_ip}"
        
        # Insertar en la tabla alerts
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute('PRAGMA journal_mode=WAL;')
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO alerts (timestamp, source_ip, destination_ip, alert_message, severity, protocol, action_taken, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_data.get('timestamp', datetime.now().isoformat()),
                src_ip,
                dest_ip,
                alert_message,
                severity,
                protocol,
                action_taken,
                json.dumps(alert_data)
            )
        )
        conn.commit()
        conn.close()
        logger.info("Alerta procesada: %s | Src: %s | Dest: %s | Severidad: %d | Acción: %s",
                    alert_message, src_ip, dest_ip, severity, action_taken)

    except Exception as e:
        logger.error("Error procesando alerta: %s", e)

# ----------------------------------------
# Watchdog Event Handler para eve.json
# ----------------------------------------
class SuricataEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        if os.path.basename(event.src_path) != "eve.json":
            return

        try:
            with open(event.src_path, 'r') as f:
                for line in f:
                    try:
                        alert_json = json.loads(line.strip())
                        if 'alert' in alert_json:
                            process_alert(alert_json)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error("Error leyendo %s: %s", event.src_path, e)

# ----------------------------------------
# API REST con Flask para consultar alertas
# ----------------------------------------
app = Flask(__name__)

@app.route('/alerts', methods=['GET'])
def get_alerts():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL;')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, src_ip, dest_ip, alert_message, severity, action_taken "
        "FROM alerts ORDER BY id DESC LIMIT 100"
    )
    rows = cursor.fetchall()
    conn.close()
    alerts_list = []
    for row in rows:
        alerts_list.append({
            'timestamp': row[0],
            'src_ip': row[1],
            'dest_ip': row[2],
            'alert_message': row[3],
            'severity': row[4],
            'action_taken': row[5]
        })
    return jsonify(alerts_list)

@app.route('/api/block-ip', methods=['POST'])
def api_block_ip():
    data = request.get_json()
    ip = data.get('ip_address')
    reason = data.get('reason', 'manual')
    if not ip or not validate_ip(ip):
        return jsonify({'success': False, 'message': 'IP inválida'}), 400
    result = block_ip(ip, reason)
    if result:
        return jsonify({'success': True, 'message': f'IP {ip} bloqueada'}), 200
    else:
        return jsonify({'success': False, 'message': f'No se pudo bloquear la IP {ip} (puede que ya esté bloqueada o error interno)'}), 500

def run_flask():
    """Inicia el servidor Flask en un thread aparte."""
    app.run(host='0.0.0.0', port=5000, threaded=True)

# ----------------------------------------
# Función principal
# ----------------------------------------
def main():
    init_database()

    log_dir = "/var/log/suricata"
    eve_path = os.path.join(log_dir, "eve.json")

    # 1) Esperar a que exista /var/log/suricata
    while not os.path.isdir(log_dir):
        logger.info("Esperando a que aparezca el directorio %s...", log_dir)
        time.sleep(1)

    # 2) (Opcional) Esperar a que exista eve.json
    # while not os.path.isfile(eve_path):
    #     logger.info("Esperando a que exista el archivo %s...", eve_path)
    #     time.sleep(1)

    # 3) Arrancar Watchdog Observer
    event_handler = SuricataEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=log_dir, recursive=False)
    observer.start()
    logger.info("Observer iniciado: vigilando %s", eve_path)

    # 4) Arrancar servidor Flask en segundo plano
    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()
    logger.info("Servidor Flask iniciado en el puerto 5000")

    try:
        # Mantener vivo el thread principal para Watchdog
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
