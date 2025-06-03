#!/usr/bin/env python3
import json
import requests
import time

def send_test_alert():
    # Datos de la alerta de prueba
    test_alert = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'src_ip': '192.168.1.100',
        'dest_ip': '192.168.1.1:80',  # Incluimos el puerto en dest_ip
        'dest_port': 80,  # Y también como campo separado
        'alert': {
            'signature': 'Prueba de alerta con puerto',
            'severity': 2
        },
        'proto': 'TCP',
        'event_type': 'alert'
    }
    
    # Convertir a JSON
    alert_json = json.dumps(test_alert)
    
    try:
        # Enviar la alerta al endpoint de la API
        response = requests.post('http://localhost:5000/alert', 
                              data=alert_json,
                              headers={'Content-Type': 'application/json'})
        print(f"Respuesta del servidor: {response.status_code}")
        print(f"Contenido: {response.text}")
    except Exception as e:
        print(f"Error al enviar la alerta: {e}")

if __name__ == "__main__":
    print("Enviando alerta de prueba...")
    send_test_alert()
