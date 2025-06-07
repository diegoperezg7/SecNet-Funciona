#!/bin/bash
set -e

# Habilitar modo de depuración si se solicita
if [ "${DEBUG:-0}" = "1" ]; then
    set -x
fi

echo "=== Iniciando contenedor responder ==="
echo "Usuario actual: $(id -un) (UID: $(id -u), GID: $(id -g))"

# Función para verificar si un comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Función para registrar mensajes con marca de tiempo
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Función para inicializar ipset
initialize_ipset() {
    log "Inicializando ipset..."
    
    # Crear directorio para reglas de ipset si no existe
    mkdir -p /etc/ipset
    
    # Crear conjuntos de ipset si no existen
    if ! ipset list blocklist >/dev/null 2>&1; then
        log "Creando conjunto blocklist IPv4..."
        ipset create blocklist hash:ip family inet hashsize 1024 maxelem 65536 || {
            log "ERROR: No se pudo crear el conjunto blocklist IPv4"
            return 1
        }
    fi
    
    if ! ipset list blocklist6 >/dev/null 2>&1; then
        log "Creando conjunto blocklist IPv6..."
        ipset create blocklist6 hash:ip family inet6 hashsize 1024 maxelem 65536 || {
            log "ERROR: No se pudo crear el conjunto blocklist IPv6"
            return 1
        }
    fi
    
    # Cargar reglas guardadas si existen
    if [ -f /etc/ipset/ipset.rules ]; then
        log "Cargando reglas de ipset desde /etc/ipset/ipset.rules..."
        ipset restore -f /etc/ipset/ipset.rules || {
            log "ADVERTENCIA: No se pudieron cargar las reglas de ipset"
            return 1
        }
    fi
    
    return 0
}

# Función para inicializar nftables
initialize_nftables() {
    log "Inicializando nftables..."
    
    # Verificar si nft está instalado
    if ! command -v nft >/dev/null 2>&1; then
        log "ADVERTENCIA: nft no está instalado, omitiendo inicialización de nftables"
        return 1
    fi
    
    # Crear directorio para reglas de nftables si no existe
    mkdir -p /etc/nftables
    
    # Cargar reglas guardadas si existen
    if [ -f /etc/nftables/nftables.rules ]; then
        log "Cargando reglas de nftables desde /etc/nftables/nftables.rules..."
        nft -f /etc/nftables/nftables.rules || {
            log "ADVERTENCIA: No se pudieron cargar las reglas de nftables"
            return 1
        }
        log "Reglas de nftables cargadas exitosamente"
        return 0
    fi
    
    # Configuración básica si no hay reglas guardadas
    log "Creando configuración básica de nftables..."
    
    # Crear una configuración básica
    cat > /tmp/nftables.conf << 'EOF'
# Configuración básica de nftables

table inet filter {
    # Conjuntos para IPs bloqueadas
    set blackhole {
        type ipv4_addr
        flags timeout
    }
    
    set blackhole6 {
        type ipv6_addr
        flags timeout
    }
    
    chain input {
        type filter hook input priority 0; policy accept;
        
        # Aceptar tráfico de loopback
        iifname "lo" accept
        
        # Aceptar conexiones establecidas
        ct state established,related accept
        
        # Aceptar pings
        icmp type echo-request accept
        
        # Bloquear IPs en la lista negra
        ip saddr @blackhole counter drop
        ip6 saddr @blackhole6 counter drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy accept;
        
        # Bloquear tráfico desde/hacia IPs en la lista negra
        ip saddr @blackhole counter drop
        ip6 saddr @blackhole6 counter drop
        ip daddr @blackhole counter drop
        ip6 daddr @blackhole6 counter drop
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        
        # Bloquear tráfico hacia IPs en la lista negra
        ip daddr @blackhole counter drop
        ip6 daddr @blackhole6 counter drop
    }
}

# Configuración adicional para Docker
# Nota: No usamos bridge family ya que no es compatible con el hook ingress en el contenedor
# En su lugar, usamos ipset con iptables para el filtrado en Docker
EOF

    # Aplicar configuración
    if nft -f /tmp/nftables.conf; then
        # Guardar configuración
        mkdir -p /etc/nftables
        nft list ruleset > /etc/nftables/nftables.rules
        log "Configuración básica de nftables aplicada y guardada"
        return 0
    else
        log "ERROR: No se pudo aplicar la configuración de nftables"
        return 1
    fi
}

# Función para inicializar iptables (como respaldo)
initialize_iptables() {
    log "Inicializando iptables (respaldo)..."
    
    # Verificar si iptables está disponible
    if ! command -v iptables >/dev/null 2>&1; then
        log "ADVERTENCIA: iptables no está instalado, omitiendo inicialización"
        return 1
    fi
    
    # Crear reglas básicas si no existen
    if ! iptables -nL >/dev/null 2>&1; then
        log "Configurando reglas básicas de iptables..."
        
        # Políticas por defecto
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        
        # Limpiar cadenas
        iptables -F
        iptables -t nat -F
        iptables -t mangle -F
        iptables -X
        
        # Aceptar conexiones establecidas
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        
        # Aceptar loopback
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        
        # Aceptar pings
        iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
        
        # Reglas para ipset
        if ipset list blocklist >/dev/null 2>&1; then
            log "Aplicando reglas de ipset..."
            # Verificar si la regla ya existe para no duplicar
            if ! iptables -C INPUT -m set --match-set blocklist src -j DROP 2>/dev/null; then
                iptables -I INPUT -m set --match-set blocklist src -j DROP
                iptables -I FORWARD -m set --match-set blocklist src -j DROP
                iptables -I FORWARD -m set --match-set blocklist dst -j DROP
                
                # Regla especial para DOCKER-USER si estamos en un entorno Docker
                if iptables -L DOCKER-USER >/dev/null 2>&1; then
                    iptables -I DOCKER-USER -m set --match-set blocklist src -j DROP
                    iptables -I DOCKER-USER -m set --match-set blocklist dst -j DROP
                fi
            fi
        fi
        
        # Guardar reglas
        save_iptables
    else
        log "iptables ya está configurado"
    fi
    
    return 0
}

# Cargar módulos del kernel necesarios
load_kernel_modules() {
    log "Cargando módulos del kernel necesarios..."
    
    # Lista de módulos necesarios
    # Agrupados por funcionalidad para mejor manejo de errores
    local modules=(
        # Módulos básicos de red
        "ip_tables"
        "ip6_tables"
        "iptable_filter"
        "ip6table_filter"
        "iptable_nat"
        "nf_tables"
        
        # Módulos de conexión y NAT
        "nf_conntrack"
        "nf_nat"
        "xt_conntrack"
        "xt_state"
        "xt_comment"
        "xt_mark"
        "xt_tcpudp"
        "xt_addrtype"
        "xt_multiport"
        
        # Módulos de red avanzados (opcionales)
        "br_netfilter"
        "overlay"
    )
    
    # Módulos que pueden fallar pero no son críticos
    local optional_modules=(
        "nf_nat_ipv4"
        "nf_nat_ipv6"
        "nf_conntrack_ipv4"
        "nf_conntrack_ipv6"
    )
    
    # Cargar módulos principales
    local mod
    for mod in "${modules[@]}"; do
        log "Cargando módulo: $mod"
        if ! modprobe "$mod" 2>/dev/null; then
            log "ADVERTENCIA: No se pudo cargar el módulo $mod"
        fi
    done
    
    # Cargar módulos opcionales
    for mod in "${optional_modules[@]}"; do
        log "Intentando cargar módulo opcional: $mod"
        if modprobe "$mod" 2>/dev/null; then
            log "Módulo opcional cargado: $mod"
        else
            log "INFO: No se pudo cargar el módulo opcional $mod - continuando sin él"
        fi
    done
    
    # Verificar módulos críticos
    local critical_modules=(
        "ip_tables"
        "iptable_filter"
        "nf_conntrack"
        "nf_tables"
    )
    
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
    else
        log "Módulos del kernel cargados correctamente"
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

# Función para guardar reglas de firewall (iptables/ipset/nftables)
save_iptables() {
    log "Guardando reglas de firewall..."
    
    # Guardar reglas de nftables si está instalado
    if command_exists nft; then
        log "Guardando reglas de nftables..."
        mkdir -p /etc/nftables
        nft list ruleset > /etc/nftables/nftables.rules 2>/dev/null || {
            log "ADVERTENCIA: No se pudieron guardar las reglas de nftables"
            # Continuar para guardar iptables/ipset como respaldo
        }
    fi
    
    # Guardar reglas de ipset si está instalado
    if command_exists ipset; then
        log "Guardando reglas de ipset..."
        mkdir -p /etc/ipset
        ipset save > /etc/ipset/ipset.rules 2>/dev/null || {
            log "ADVERTENCIA: No se pudieron guardar las reglas de ipset"
            # Continuar para guardar iptables
        }
    fi
    
    # Guardar reglas de iptables (como respaldo)
    if command_exists iptables; then
        log "Guardando reglas de iptables..."
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || {
            log "ADVERTENCIA: No se pudieron guardar las reglas IPv4 de iptables"
        }
        
        if command_exists ip6tables; then
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || {
                log "ADVERTENCIA: No se pudieron guardar las reglas IPv6 de iptables"
            }
        fi
    fi
    
    # Intentar guardar reglas persistentemente si está disponible
    if command_exists netfilter-persistent; then
        log "Guardando reglas persistentemente usando netfilter-persistent..."
        netfilter-persistent save || {
            log "ADVERTENCIA: No se pudieron guardar las reglas persistentemente"
        }
    elif command_exists iptables-persistent; then
        log "Guardando reglas persistentemente usando iptables-persistent..."
        iptables-persistent save || {
            log "ADVERTENCIA: No se pudieron guardar las reglas persistentemente"
        }
    fi
    
    log "Reglas de firewall guardadas correctamente"
    return 0
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

# Función para asegurar permisos de directorios
ensure_directories() {
    log "Asegurando permisos de directorios..."
    
    # Crear directorios necesarios si no existen
    sudo mkdir -p /run/xtables.lock /run/ipset /etc/iptables /etc/ipset 2>/dev/null || {
        log "ADVERTENCIA: No se pudieron crear los directorios con sudo, intentando sin permisos elevados..."
        mkdir -p /run/xtables.lock /run/ipset /etc/iptables /etc/ipset 2>/dev/null || {
            log "ERROR: No se pudieron crear los directorios necesarios"
            return 1
        }
    }
    
    # Establecer permisos adecuados
    sudo chmod 1777 /run/xtables.lock /run/ipset 2>/dev/null || chmod 1777 /run/xtables.lock /run/ipset 2>/dev/null || {
        log "ADVERTENCIA: No se pudieron establecer los permisos en /run"
    }
    
    sudo chmod 755 /etc/iptables /etc/ipset 2>/dev/null || chmod 755 /etc/iptables /etc/ipset 2>/dev/null || {
        log "ADVERTENCIA: No se pudieron establecer los permisos en /etc"
    }
    
    # Asegurar que el usuario appuser tenga acceso (si es posible)
    if [ "$(id -u)" -eq 0 ]; then
        chown -R appuser:appuser /run/xtables.lock /run/ipset /etc/iptables /etc/ipset 2>/dev/null || {
            log "ADVERTENCIA: No se pudo cambiar el propietario de los directorios"
        }
    fi
    
    return 0
}

# Función principal
main() {
    # Configurar el entorno
    setup_environment
    
    # Asegurar permisos de directorios
    ensure_directories
    
    # Cargar módulos del kernel necesarios
    load_kernel_modules
    
    # Configurar la base de datos
    setup_database
    
    # Intentar inicializar nftables primero (sistema más moderno)
    if command_exists nft; then
        log "Intentando inicializar nftables..."
        if initialize_nftables; then
            log "nftables inicializado correctamente"
            # Si nftables se inicializó correctamente, podemos omitir ipset/iptables
            log "Iniciando el servicio de la API con nftables..."
            exec python3 /app/responder.py
            exit 0
        else
            log "ADVERTENCIA: No se pudo inicializar nftables, intentando con ipset/iptables..."
        fi
    else
        log "ADVERTENCIA: nft no está instalado, usando ipset/iptables"
    fi
    
    # Si llegamos aquí, nftables no está disponible o falló, usar ipset/iptables
    
    # Inicializar ipset si está disponible
    if command_exists ipset; then
        if ! initialize_ipset; then
            log "ADVERTENCIA: No se pudo inicializar ipset correctamente"
        else
            log "ipset inicializado correctamente"
        fi
    else
        log "ADVERTENCIA: ipset no está instalado. El bloqueo de IPs será menos eficiente."
    fi
    
    # Inicializar iptables
    if ! initialize_iptables; then
        log "ERROR: No se pudo inicializar iptables correctamente"
        exit 1
    fi
    
    # Configurar iptables
    if ! setup_iptables; then
        log "ERROR: No se pudo configurar iptables correctamente"
        exit 1
    fi
    
    # Guardar las reglas actuales
    if ! save_iptables; then
        log "ADVERTENCIA: No se pudieron guardar las reglas de iptables"
    fi
    
    # Iniciar el servicio de la API
    log "Iniciando el servicio de la API con iptables..."
    exec python3 /app/responder.py
}

# Ejecutar función principal
main "$@"
