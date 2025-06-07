#!/bin/bash
set -e

# Habilitar modo de depuración si se solicita
if [ "${DEBUG:-0}" = "1" ]; then
    set -x
fi

echo "=== Iniciando contenedor responder ==="
echo "Usuario actual: $(id -un) (UID: $(id -u), GID: $(id -g))"

# Función para registrar mensajes con marca de tiempo
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Función para inicializar iptables
initialize_iptables() {
    log "Inicializando iptables..."
    
    # Crea el archivo de reglas si no existe
    if [ ! -f /etc/iptables/rules.v4 ]; then
        log "Creando archivo de reglas iptables inicial..."
        iptables-save > /etc/iptables/rules.v4 || {
            log "ERROR: No se pudo guardar las reglas iptables. ¿Ejecutando como root?"
            return 1
        }
        chmod 644 /etc/iptables/rules.v4
    fi
    
    # Carga las reglas si existen
    if [ -f /etc/iptables/rules.v4 ]; then
        log "Cargando reglas iptables desde /etc/iptables/rules.v4..."
        iptables-restore < /etc/iptables/rules.v4 || {
            log "ADVERTENCIA: No se pudieron cargar las reglas iptables"
            return 1
        }
    fi
    
    return 0
}

# Cargar módulos del kernel necesarios
load_kernel_modules() {
    log "Cargando módulos del kernel necesarios..."
    
    # Lista de módulos necesarios
    local modules=(
        "ip_tables"
        "iptable_filter"
        "iptable_nat"
        "nf_conntrack"
        "nf_nat"
        "xt_conntrack"
        "xt_state"
        "xt_comment"
        "xt_mark"
        "xt_tcpudp"
        "xt_addrtype"
        "xt_multiport"
        "ip6_tables"
        "ip6table_filter"
        "nf_tables"
        "nf_nat_ipv4"
        "nf_conntrack_ipv4"
        "nf_nat_ipv6"
        "nf_conntrack_ipv6"
    )
    
    # Cargar cada módulo
    for mod in "${modules[@]}"; do
        if ! lsmod | grep -q "^${mod}"; then
            log "Cargando módulo: $mod"
            if ! modprobe "$mod" 2>/dev/null; then
                log "ADVERTENCIA: No se pudo cargar el módulo $mod"
            fi
        fi
    done
    
    # Verificar módulos críticos
    local critical_modules=("ip_tables" "iptable_filter" "nf_conntrack")
    local all_loaded=true
    for mod in "${critical_modules[@]}"; do
        if ! lsmod | grep -q "^${mod}"; then
            log "ERROR: No se pudo cargar el módulo crítico: $mod"
            all_loaded=false
        fi
    done
    
    if [ "$all_loaded" = false ]; then
        log "ERROR: No se pudieron cargar todos los módulos críticos. Es posible que el contenedor no funcione correctamente."
        log "Módulos cargados actualmente:"
        lsmod | grep -E '^ip|^nf|^xt|^bridge|^br_netfilter|^overlay'
    fi
}

# Función para configurar iptables
setup_iptables() {
    log "Configurando iptables..."
    
    # Asegurar que el directorio de iptables existe con los permisos correctos
    mkdir -p /etc/iptables
    chmod 755 /etc/iptables
    
    # Establecer políticas por defecto (ACCEPT para permitir el tráfico por defecto)
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Limpiar todas las reglas existentes
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    iptables -X
    iptables -t nat -X
    iptables -t mangle -X
    
    # Cargar reglas guardadas si existen
    if [ -f /etc/iptables/rules.v4 ]; then
        log "Cargando reglas de iptables desde /etc/iptables/rules.v4..."
        if ! iptables-restore < /etc/iptables/rules.v4; then
            log "ERROR: No se pudieron cargar las reglas de iptables. Iniciando con configuración por defecto."
            # Configuración por defecto mínima
            iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A FORWARD -i docker0 -o eth0 -j ACCEPT
            iptables -A FORWARD -i eth0 -o docker0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        else
            log "Reglas de iptables cargadas correctamente."
        fi
    else
        log "No se encontró archivo de reglas. Usando configuración por defecto."
        # Configuración por defecto mínima
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A FORWARD -i docker0 -o eth0 -j ACCEPT
        iptables -A FORWARD -i eth0 -o docker0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi
    
    # Guardar las reglas actuales
    save_iptables
}

# Función para guardar reglas de iptables
save_iptables() {
    log "Guardando reglas de iptables..."
    
    # Asegurar que el directorio existe
    mkdir -p /etc/iptables
    
    # Intentar guardar las reglas
    if iptables-save > /etc/iptables/rules.v4; then
        chmod 644 /etc/iptables/rules.v4
        log "Reglas de iptables guardadas correctamente en /etc/iptables/rules.v4"
        return 0
    else
        log "ERROR: No se pudieron guardar las reglas de iptables"
        return 1
    fi
}

# Función para configurar la base de datos
setup_database() {
    log "Configurando base de datos..."
    
    # Asegurar que el directorio existe con los permisos correctos
    mkdir -p /app/database
    chmod 777 -R /app/database
    
    # Verificar si la base de datos existe, si no, crearla
    if [ ! -f "/app/database/responder.db" ]; then
        log "Creando nueva base de datos..."
        sqlite3 /app/database/responder.db """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            reason TEXT,
            is_blocked BOOLEAN DEFAULT 1
        );
        """
        chmod 666 /app/database/responder.db
        log "Base de datos creada en /app/database/responder.db"
    else
        log "Base de datos existente encontrada en /app/database/responder.db"
    fi
}

# Función para configurar el entorno
setup_environment() {
    # Configurar zona horaria si se proporciona
    if [ -n "$TZ" ]; then
        # Set timezone using TZ environment variable instead of creating symlink
        export TZ
        log "Zona horaria configurada a: $TZ"
    fi
    
    # Configurar locale si es necesario
    if [ -n "$LANG" ]; then
        export LANG
        log "Idioma configurado a: $LANG"
    fi
}

# Función principal
main() {
    log "Iniciando configuración del entorno..."
    
    # Configurar entorno
    setup_environment
    
    # Cargar módulos del kernel
    load_kernel_modules
    
    # Inicializar iptables
    initialize_iptables || {
        log "ADVERTENCIA: No se pudo inicializar iptables. Algunas funciones pueden no estar disponibles."
    }
    
    # Configurar iptables (reglas personalizadas)
    setup_iptables || {
        log "ADVERTENCIA: No se pudo configurar iptables. Continuando sin configuración personalizada."
    }
    
    # Configurar base de datos
    setup_database
    
    log "Iniciando el servicio responder..."
    
    # Ejecutar el script de Python
    exec python3 /app/responder.py
}

# Ejecutar función principal
main "$@"
