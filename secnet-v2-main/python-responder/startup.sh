#!/bin/bash
set -e

echo "Starting up with UID: $(id -u)"

# Asegurar que los módulos de kernel necesarios estén cargados
modprobe ip_tables || true
modprobe iptable_filter || true
modprobe iptable_nat || true
modprobe nf_conntrack || true
modprobe nf_nat || true

# Asegurar que el directorio de iptables existe con los permisos correctos
echo "Configurando directorio de iptables..."
mkdir -p /etc/iptables
chmod 755 /etc/iptables

# Función para cargar reglas de iptables
load_iptables_rules() {
    echo "Cargando reglas de iptables..."
    if [ -f /etc/iptables/rules.v4 ]; then
        # Crear un archivo temporal para limpiar las reglas existentes
        echo "*filter" > /tmp/iptables.rules
        echo ":INPUT ACCEPT [0:0]" >> /tmp/iptables.rules
        echo ":FORWARD ACCEPT [0:0]" >> /tmp/iptables.rules
        echo ":OUTPUT ACCEPT [0:0]" >> /tmp/iptables.rules
        echo "COMMIT" >> /tmp/iptables.rules
        
        # Aplicar reglas limpias
        iptables-restore < /tmp/iptables.rules
        
        # Cargar las reglas guardadas
        iptables-restore < /etc/iptables/rules.v4
        
        # Asegurar que las políticas por defecto son ACCEPT
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        
        echo "Reglas de iptables cargadas correctamente."
    else
        echo "No se encontró el archivo de reglas de iptables. Se iniciará con reglas por defecto."
        # Establecer políticas por defecto
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
    fi
}

# Función para guardar reglas de iptables
save_iptables_rules() {
    echo "Guardando reglas de iptables..."
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    chmod 644 /etc/iptables/rules.v4
    echo "Reglas de iptables guardadas en /etc/iptables/rules.v4"
}

# Cargar reglas al inicio
load_iptables_rules

# Configurar trap para guardar reglas al salir
trap 'save_iptables_rules' EXIT

# Asegurar permisos del directorio de la base de datos
echo "Configurando permisos de la base de datos..."
mkdir -p /app/database
chmod 777 -R /app/database

# Iniciar el respondedor
echo "Iniciando el respondedor..."
exec python responder.py
