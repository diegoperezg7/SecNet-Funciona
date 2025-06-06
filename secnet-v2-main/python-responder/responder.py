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
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
DB_PATH = os.path.join(DB_DIR, 'alerts.db')

# Asegurarse de que el directorio de la base de datos existe
os.makedirs(DB_DIR, exist_ok=True)
os.chmod(DB_DIR, 0o777)  # Asegurar permisos de escritura

def init_database():
    """Inicializa la base de datos SQLite si no existe."""
    db_dir = os.path.dirname(DB_PATH)
    if not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, mode=0o777, exist_ok=True)
        except PermissionError as e:
            print(f"Warning: Could not create directory {db_dir}: {e}")
    
    # Try to set permissions on directory if it exists
    if os.path.exists(db_dir):
        try:
            os.chmod(db_dir, 0o777)
        except PermissionError as e:
            print(f"Warning: Could not set permissions on directory {db_dir}: {e}")
    
    # Connect to the database
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL;')
    cursor = conn.cursor()
    
    # Try to set permissions on the database file
    if os.path.exists(DB_PATH):
        try:
            os.chmod(DB_PATH, 0o666)
        except (PermissionError, OSError) as e:
            print(f"Warning: Could not set permissions on {DB_PATH}: {e}")
            print("Continuing with current permissions...")
            # Continue anyway, as the database might still be usable
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        source_port TEXT,
        destination_ip TEXT,
        dest_port TEXT,
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
def is_ip_blocked_in_iptables(ip_address):
    """
    Verifica si una IP ya está bloqueada en iptables.
    
    Args:
        ip_address (str): La dirección IP a verificar
        
    Returns:
        bool: True si la IP ya está bloqueada, False en caso contrario
    """
    try:
        # Verificar en la cadena INPUT
        cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return True
            
        # Verificar en la cadena DOCKER-USER si existe
        cmd = ["iptables", "-C", "DOCKER-USER", "-s", ip_address, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return True
            
        return False
    except Exception as e:
        logger.error(f"Error al verificar IP en iptables: {e}")
        return False

def block_ip(ip_address, reason):
    """
    Bloquea una IP usando iptables y la registra en la BD.
    
    Args:
        ip_address (str): La dirección IP a bloquear
        reason (str): Razón del bloqueo
        
    Returns:
        bool: True si el bloqueo fue exitoso, False en caso contrario
    """
    try:
        logger.info(f"Intentando bloquear IP: {ip_address} - Razón: {reason}")
        if not validate_ip(ip_address):
            logger.error("IP inválida: %s", ip_address)
            return False
            
        # Verificar si ya está bloqueada en iptables
        if is_ip_blocked_in_iptables(ip_address):
            logger.info(f"La IP {ip_address} ya está bloqueada en iptables")
            return True
        
        # Conectar a la base de datos
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute('PRAGMA journal_mode=WAL;')
        cursor = conn.cursor()
        
        # Verificar si la IP ya está en la base de datos
        cursor.execute("SELECT * FROM blocked_ips WHERE ip_address = ?", (ip_address,))
        if not cursor.fetchone():
            # Registrar el bloqueo en la base de datos si no existe
            timestamp = datetime.now().isoformat()
            cursor.execute(
                "INSERT INTO blocked_ips (ip_address, timestamp, reason) VALUES (?, ?, ?)",
                (ip_address, timestamp, reason)
            )
            conn.commit()
        
        conn.close()
        
        # Función para ejecutar comandos con manejo de errores
        def run_command(cmd, use_sudo=False):
            try:
                if use_sudo:
                    cmd = ["sudo"] + cmd
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                return True, result
            except subprocess.CalledProcessError as e:
                logger.error("Error al ejecutar comando %s: %s", " ".join(cmd), e.stderr or str(e))
                return False, e
        
        # Comandos para bloquear la IP
        iptables_cmds = [
            # Bloquear tráfico entrante
            ["iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"],
            # Bloquear tráfico saliente (opcional, dependiendo de tus necesidades)
            # ["iptables", "-I", "OUTPUT", "1", "-d", ip_address, "-j", "DROP"],
            # Bloquear en la cadena DOCKER-USER si existe
            ["sh", "-c", f"iptables -C DOCKER-USER -j RETURN 2>/dev/null && iptables -I DOCKER-USER 1 -s {ip_address} -j DROP || true"],
            # Asegurarse de que el directorio para guardar las reglas existe
            ["sh", "-c", "mkdir -p /etc/iptables"],
            # Guardar las reglas de iptables
            ["sh", "-c", "iptables-save > /etc/iptables/rules.v4"]
        ]
        
        # Ejecutar comandos de bloqueo
        for cmd in iptables_cmds:
            success, _ = run_command(cmd)
            if not success and cmd[0] != "sh":  # Ignorar fallos en comandos de shell complejos
                logger.error(f"Error al ejecutar comando: {' '.join(cmd)}")
                return False
                
        # Verificar que la IP esté realmente bloqueada
        if not is_ip_blocked_in_iptables(ip_address):
            logger.error(f"No se pudo verificar el bloqueo de la IP {ip_address} en iptables")
            return False
            
        logger.info(f"IP {ip_address} bloqueada correctamente en iptables")
        return True
        
        # Guardar las reglas de iptables para que persistan
        save_commands = [
            ["which", "iptables-persistent"],
            ["which", "netfilter-persistent"],
            ["which", "iptables-save"]
        ]
        
        saved = False
        for cmd in save_commands:
            if run_command(cmd)[0]:
                if "iptables-persistent" in cmd[1]:
                    success, _ = run_command(["sh", "-c", "iptables-save > /etc/iptables/rules.v4"])
                    if success:
                        saved = True
                        break
                elif "netfilter-persistent" in cmd[1]:
                    success, _ = run_command(["netfilter-persistent", "save"])
                    if success:
                        saved = True
                        break
                elif "iptables-save" in cmd[1]:
                    success, _ = run_command(["sh", "-c", "iptables-save > /etc/iptables/rules.v4"])
                    if success:
                        saved = True
                        break
        
        if not saved:
            logger.warning("No se pudo guardar las reglas de iptables de forma persistente")
        else:
            logger.info("Reglas de iptables guardadas correctamente")
        
        logger.info("IP %s bloqueada correctamente", ip_address)
        return True
        
    except Exception as e:
        logger.error("Error en block_ip() para IP %s: %s", ip_address, str(e), exc_info=True)
        return False

def unblock_ip(ip_address):
    """
    Desbloquea una IP de iptables y la elimina de la BD.
    
    Args:
        ip_address (str): La dirección IP a desbloquear
        
    Returns:
        bool: True si el desbloqueo fue exitoso, False en caso contrario
    """
    try:
        if not validate_ip(ip_address):
            logger.error("IP inválida: %s", ip_address)
            return False
            
        # Función para ejecutar comandos con manejo de errores
        def run_command(cmd, use_sudo=False):
            try:
                if use_sudo:
                    cmd = ["sudo"] + cmd
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                return True, result
            except subprocess.CalledProcessError as e:
                # Ignorar errores de reglas que no existen
                if "does a matching" in (e.stderr or "") or "Bad rule" in (e.stderr or ""):
                    return True, None
                logger.error("Error al ejecutar comando %s: %s", " ".join(cmd), e.stderr or str(e))
                return False, e
        
        # Comandos para desbloquear la IP
        iptables_cmds = [
            # Eliminar reglas de bloqueo entrante (todas las ocurrencias)
            ["sh", "-c", f"while iptables -D INPUT -s {ip_address} -j DROP 2>/dev/null; do :; done"],
            # Eliminar reglas de bloqueo saliente (todas las ocurrencias)
            ["sh", "-c", f"while iptables -D OUTPUT -d {ip_address} -j DROP 2>/dev/null; do :; done"],
            # Eliminar reglas de la cadena DOCKER-USER si existen
            ["sh", "-c", f"iptables -C DOCKER-USER -j RETURN 2>/dev/null && while iptables -D DOCKER-USER -s {ip_address} -j DROP 2>/dev/null; do :; done || true"],
        ]
        
        # Ejecutar comandos de desbloqueo
        for cmd in iptables_cmds:
            success, _ = run_command(cmd)
            if not success:
                # Intentar con sudo
                success_sudo, _ = run_command(cmd, use_sudo=True)
                if not success_sudo:
                    logger.error("No se pudo ejecutar el comando con sudo: %s", " ".join(cmd))
        
        # Guardar cambios si netfilter-persistent está disponible
        if run_command(["which", "netfilter-persistent"])[0]:
            save_cmd = ["netfilter-persistent", "save"]
            success, _ = run_command(save_cmd)
            if not success:
                run_command(save_cmd, use_sudo=True)
        else:
            # Alternativa para guardar reglas manualmente
            save_manual = ["sh", "-c", "iptables-save > /etc/iptables/rules.v4"]
            success, _ = run_command(save_manual)
            if not success:
                run_command(save_manual, use_sudo=True)
        
        # Eliminar de la base de datos
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
            conn.commit()
            conn.close()
            logger.info("IP %s eliminada de la base de datos", ip_address)
        except Exception as db_error:
            logger.error("Error al eliminar IP %s de la base de datos: %s", ip_address, db_error)
            # Continuar aunque falle la BD
        
        logger.info("IP %s desbloqueada correctamente en todas las cadenas", ip_address)
        return True
        
    except Exception as e:
        logger.error("Error en unblock_ip() para IP %s: %s", ip_address, str(e), exc_info=True)
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
    
    # Usamos la gravedad directamente del JSON
    # severity 1 = Baja
    # severity 2 = Media
    # severity 3 = Alta
    severity = int(alert_data.get('alert', {}).get('severity', 1))  # Por defecto baja gravedad
    
    # --- HTTP interno: siempre gravedad 1 ---
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
        
    # --- Clasificar según gravedad ---
    if severity == 3:  # Alta gravedad
        return 'Amenaza confirmada', severity
    elif severity == 2:  # Media gravedad
        return 'Actividad sospechosa', severity
    else:  # Baja gravedad (1)
        return 'Actividad normal', severity

def parse_suricata_timestamp(timestamp_str):
    """Parsea el formato de timestamp de Suricata a un objeto datetime."""
    try:
        # Intenta analizar el timestamp directamente
        return datetime.fromisoformat(timestamp_str)
    except ValueError:
        try:
            # Si falla, intenta manejar el formato sin los dos puntos en el offset
            if timestamp_str[-3] == ':' or timestamp_str[-5] == ':':
                # Ya tiene los dos puntos, debería funcionar
                return datetime.fromisoformat(timestamp_str)
            # Añade los dos puntos en el offset de la zona horaria (ej: +0200 -> +02:00)
            if '+' in timestamp_str and timestamp_str.count('+') == 1:
                plus_pos = timestamp_str.rfind('+')
                timestamp_str = f"{timestamp_str[:plus_pos+3]}:{timestamp_str[plus_pos+3:]}"
            elif '-' in timestamp_str and timestamp_str.count('-') == 3:  # Para zonas horarias negativas
                minus_pos = timestamp_str.rfind('-')
                if len(timestamp_str) > minus_pos + 2:  # Asegurarse de que hay dígitos después del signo
                    timestamp_str = f"{timestamp_str[:minus_pos+3]}:{timestamp_str[minus_pos+3:]}"
            return datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.error(f"Error al analizar timestamp {timestamp_str}: {e}")
            return datetime.now()

def process_alert(alert_data):
    """Procesa una alerta de Suricata y toma las acciones necesarias."""
    try:
        logger.info(f"Procesando alerta: {json.dumps(alert_data, indent=2)}")
        
        # Obtener y formatear el timestamp
        timestamp_str = alert_data.get('timestamp')
        try:
            timestamp = parse_suricata_timestamp(timestamp_str) if timestamp_str else datetime.now()
        except Exception as e:
            logger.error(f"Error parseando timestamp {timestamp_str}: {e}")
            timestamp = datetime.now()
        
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
        categoria, nueva_gravedad = classify_alert(alert_data)
        
        # Determinar acción según categoría/gravedad
        if categoria == 'Tráfico interno seguro':
            severity = 1
            action_taken = "Tráfico interno seguro"
            logger.info("Registrando tráfico interno seguro: %s de %s a %s", alert_message, src_ip, dest_ip)
        elif categoria == 'HTTP interno bajo':
            severity = 1
            action_taken = "Tráfico HTTP interno registrado"
        elif categoria == 'Tráfico legítimo externo':
            severity = 1
            action_taken = "Tráfico legítimo externo registrado"
        else:
            severity = nueva_gravedad
            action_taken = "Registrado"
            
            # Bloquear IPs maliciosas - Solo para gravedad 2 o 3
            should_block = (
                severity in [2, 3] and  # Solo bloquear si la gravedad es 2 o 3
                src_ip and
                src_ip not in LOCAL_IPS and 
                src_ip not in SAFE_IPS and
                src_ip != dest_ip  # No bloquear si la IP origen y destino son la misma
            )
            
            # Debug: Mostrar información sobre la decisión de bloqueo
            logger.info(f"Evaluando bloqueo para {src_ip}: categoria={categoria}, gravedad={severity}, should_block={should_block}")
            
            if should_block:
                # Verificar si la IP ya está bloqueada en iptables
                if is_ip_blocked_in_iptables(src_ip):
                    action_taken = f"IP ya bloqueada: {src_ip}"
                    logger.info(f"La IP {src_ip} ya estaba bloqueada en iptables")
                else:
                    # Intentar bloquear la IP
                    if block_ip(src_ip, f"{alert_message} [{categoria}]"):
                        action_taken = f"IP Bloqueada: {src_ip}"
                        logger.warning(f"IP bloqueada automáticamente: {src_ip} - Razón: {alert_message}")
                        
                        # Verificar nuevamente si se bloqueó correctamente
                        if not is_ip_blocked_in_iptables(src_ip):
                            logger.error(f"La IP {src_ip} no se bloqueó correctamente en iptables")
                            action_taken = f"Error: No se pudo bloquear {src_ip}"
                    else:
                        action_taken = f"Error bloqueando IP: {src_ip}"
                        logger.error(f"No se pudo bloquear la IP: {src_ip}")
        
        # Obtener puertos
        src_port = alert_data.get('src_port', '')
        dest_port = alert_data.get('dest_port', '')
        
        # Insertar en la tabla alerts
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            conn.execute('PRAGMA journal_mode=WAL;')
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alerts (
                    timestamp, source_ip, source_port, destination_ip, dest_port, 
                    alert_message, severity, protocol, action_taken, raw_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp.isoformat(),
                    src_ip,
                    src_port,
                    dest_ip,
                    dest_port,
                    alert_message,
                    severity,
                    protocol,
                    action_taken,
                    json.dumps(alert_data)
                )
            )
            conn.commit()
            logger.info(f"Alerta guardada en la base de datos: {cursor.lastrowid}")
        except sqlite3.Error as e:
            logger.error(f"Error al guardar en la base de datos: {e}")
            # Intentar recrear la base de datos si hay un error de esquema
            if "no such table" in str(e).lower():
                logger.info("Recreando la base de datos...")
                init_database()
        except Exception as e:
            logger.error(f"Error inesperado al guardar en la base de datos: {e}")
        finally:
            if 'conn' in locals():
                conn.close()
        logger.info("Alerta procesada: %s | Src: %s | Dest: %s | Severidad: %d | Acción: %s",
                    alert_message, src_ip, dest_ip, severity, action_taken)

    except Exception as e:
        logger.error("Error procesando alerta: %s", e)

# ----------------------------------------
# Watchdog Event Handler para eve.json
# ----------------------------------------
class SuricataEventHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.last_position = 0  # Guarda la última posición leída
        self.file_size = 0
        # Obtener la marca de tiempo de inicio
        self.start_time = datetime.now().timestamp()
        self.eve_file = "/var/log/suricata/eve.json"
        logger.info("Iniciando monitoreo de eventos nuevos (desde %s)", 
                   datetime.fromtimestamp(self.start_time).isoformat())
        
        # Verificar si el archivo existe y es accesible
        if not os.path.exists(self.eve_file):
            logger.error(f"El archivo {self.eve_file} no existe")
        elif not os.access(self.eve_file, os.R_OK):
            logger.error(f"No se puede leer el archivo {self.eve_file}. Permiso denegado.")
        else:
            logger.info(f"Monitoreando archivo: {self.eve_file}")
            # Inicializar la posición al final del archivo si existe
            try:
                with open(self.eve_file, 'r') as f:
                    f.seek(0, 2)  # Ir al final del archivo
                    self.last_position = f.tell()
                    logger.info(f"Posición inicial del archivo: {self.last_position}")
            except Exception as e:
                logger.error(f"Error al inicializar la posición del archivo: {e}")

    def on_modified(self, event):
        if event.is_directory or os.path.basename(event.src_path) != "eve.json":
            return

        try:
            logger.info(f"Archivo modificado: {event.src_path}")
            self.process_eve_file()
        except Exception as e:
            logger.error(f"Error en on_modified: {e}", exc_info=True)
    
    def process_eve_file(self):
        """Procesa el archivo eve.json y extrae las alertas."""
        try:
            # Verificar si el archivo existe y es accesible
            if not os.path.exists(self.eve_file):
                logger.warning(f"El archivo {self.eve_file} no existe")
                return
                
            if not os.access(self.eve_file, os.R_OK):
                logger.error(f"No se puede leer el archivo {self.eve_file}. Permiso denegado.")
                return
                
            with open(self.eve_file, 'r', errors='replace') as f:
                # Obtener el tamaño actual del archivo
                current_size = os.path.getsize(self.eve_file)
                logger.debug(f"Tamaño actual del archivo: {current_size}, última posición: {self.last_position}")
                
                # Si el archivo se ha reducido (rotación de logs), reiniciar la posición
                if current_size < self.last_position:
                    logger.info(f"Archivo rotado detectado. Tamaño actual: {current_size}, última posición: {self.last_position}")
                    self.last_position = 0
                
                # Si no hay contenido nuevo, salir
                if self.last_position >= current_size:
                    return
                
                # Ir a la última posición leída y leer el contenido nuevo
                f.seek(self.last_position)
                new_content = f.read(current_size - self.last_position)
                
                # Actualizar la última posición
                self.last_position = current_size
                
                # Procesar cada línea del contenido nuevo
                for line in new_content.splitlines():
                    self.process_line(line.strip())
                
                # Actualizar el tamaño del archivo después de procesar las líneas
                self.file_size = current_size
                
        except Exception as e:
            logger.error(f"Error procesando el archivo {self.eve_file}: {e}", exc_info=True)
    
    def process_line(self, line):
        """Procesa una línea del archivo de registro."""
        if not line:
            return
            
        try:
            alert_json = json.loads(line)
            # Solo procesar si es una alerta y es posterior al inicio del servicio
            if 'alert' in alert_json:
                try:
                    # Intentar con el formato con zona horaria con :
                    alert_time = datetime.strptime(alert_json.get('timestamp', '1970-01-01T00:00:00+0000'), '%Y-%m-%dT%H:%M:%S%z')
                except ValueError:
                    try:
                        # Intentar con el formato sin zona horaria
                        alert_time = datetime.strptime(alert_json.get('timestamp', '1970-01-01T00:00:00'), '%Y-%m-%dT%H:%M:%S.%f')
                    except ValueError:
                        # Si no se puede analizar, usar la hora actual
                        alert_time = datetime.now()
                
                if alert_time.timestamp() >= self.start_time:
                    logger.info(f"Procesando nueva alerta: {alert_json.get('alert', {}).get('signature', 'Desconocida')}")
                    process_alert(alert_json)
        except json.JSONDecodeError as e:
            logger.error(f"Error decodificando JSON: {e}. Línea: {line}")
        except Exception as e:
            logger.error(f"Error procesando línea: {e}", exc_info=True)

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

@app.route('/api/unblock-ip', methods=['POST'])
def api_unblock_ip():
    data = request.get_json()
    ip = data.get('ip_address')
    if not ip or not validate_ip(ip):
        return jsonify({'success': False, 'message': 'IP inválida'}), 400
    
    # Verificar si la IP está realmente bloqueada antes de intentar desbloquear
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL;')
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address FROM blocked_ips WHERE ip_address = ?", (ip,))
    is_blocked_in_db = cursor.fetchone()
    conn.close()

    if not is_blocked_in_db:
        # Si no está en la BD, intentamos quitarla de iptables por si acaso quedó alguna regla huérfana
        # pero informamos que no estaba en la BD.
        unblock_result = unblock_ip(ip) # unblock_ip ya maneja iptables y BD
        if unblock_result:
            return jsonify({'success': True, 'message': f'IP {ip} desbloqueada (no estaba en la base de datos pero se intentó limpiar de iptables)'}), 200
        else:
            return jsonify({'success': False, 'message': f'IP {ip} no encontrada en la base de datos y no se pudo limpiar de iptables (o no existía regla)'}), 404

    # Si está en la BD, proceder con el desbloqueo normal
    result = unblock_ip(ip)
    if result:
        return jsonify({'success': True, 'message': f'IP {ip} desbloqueada correctamente'}), 200
    else:
        return jsonify({'success': False, 'message': f'No se pudo desbloquear la IP {ip} (error interno)'}), 500

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
