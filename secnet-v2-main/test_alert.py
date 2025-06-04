#!/usr/bin/env python3
import json
import os
from datetime import datetime

def create_test_alert():
    # Crear una alerta de prueba en formato Suricata EVE
    test_alert = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "flow_id": 1234567890123456,
        "in_iface": "eth0",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dest_ip": "192.168.1.1",
        "dest_port": 80,
        "proto": "TCP",
        "pkt_src": "wire/pcap",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 1,
            "rev": 1,
            "signature": "Test Alert",
            "category": "Test Alert Category",
            "severity": 2
        },
        "direction": "to_server",
        "flow": {
            "pkts_toserver": 1,
            "pkts_toclient": 0,
            "bytes_toserver": 60,
            "bytes_toclient": 0,
            "start": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "src_ip": "192.168.1.100",
            "dest_ip": "192.168.1.1",
            "src_port": 54321,
            "dest_port": 80
        }
    }
    
    return test_alert

def append_alert_to_eve(alert):
    # Ruta al archivo eve.json
    eve_file = "logs/eve.json"  # Ruta relativa al directorio del proyecto
    
    # Si el archivo no existe, crearlo vacío
    if not os.path.exists(eve_file):
        open(eve_file, 'w').close()
    
    # Agregar la alerta al final del archivo (formato JSON Lines)
    with open(eve_file, 'a') as f:
        f.write(json.dumps(alert) + '\n')
    
    print(f"Alerta de prueba agregada a {eve_file}")

if __name__ == "__main__":
    alert = create_test_alert()
    append_alert_to_eve(alert)
    print("Alerta de prueba creada exitosamente.")
    print("Verifica los logs del contenedor python-responder para confirmar que la alerta fue procesada.")
