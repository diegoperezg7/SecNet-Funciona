#!/bin/bash
# Script de inicialización de nftables para el contenedor

set -e

# Configuración básica de nftables
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

# Configuración adicional para Docker si es necesario
table bridge filter {
    chain DOCKER-USER {
        type filter hook ingress priority -150; policy accept;
        
        # Bloquear tráfico desde/hacia IPs en la lista negra
        ip saddr @blackhole counter drop
        ip6 saddr @blackhole6 counter drop
        ip daddr @blackhole counter drop
        ip6 daddr @blackhole6 counter drop
    }
}
EOF

# Aplicar configuración
if nft -f /tmp/nftables.conf; then
    # Guardar configuración
    mkdir -p /etc/nftables
    nft list ruleset > /etc/nftables/nftables.rules
    echo "Configuración de nftables aplicada correctamente"
    exit 0
else
    echo "ERROR: No se pudo aplicar la configuración de nftables"
    exit 1
fi
