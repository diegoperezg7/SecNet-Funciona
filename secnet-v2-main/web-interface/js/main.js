document.addEventListener('DOMContentLoaded', function() {
    // Configurar botón de bloqueo de IP
    const blockButtons = document.querySelectorAll('.block-button');
    blockButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('¿Está seguro de que desea bloquear esta dirección IP?')) {
                e.preventDefault();
            }
        });
    });

    // Agregar marca de tiempo de actualización
    const footer = document.querySelector('footer');
    if (footer) {
        const timestamp = document.createElement('p');
        timestamp.classList.add('refresh-time');
        timestamp.textContent = 'Última actualización: ' + new Date().toLocaleTimeString();
        footer.prepend(timestamp);
    }
    
    // Botón de carga de mapa
    const loadMapBtn = document.getElementById('loadMapBtn');
    if (loadMapBtn) {
        loadMapBtn.addEventListener('click', function() {
            const mapPlaceholder = document.getElementById('mapPlaceholder');
            if (mapPlaceholder) {
                mapPlaceholder.innerHTML = '<p>Cargando datos del mapa...</p>';
                
                // Simular carga
                setTimeout(() => {
                    mapPlaceholder.innerHTML = '<p>Datos de geolocalización cargados</p><p>10 países únicos detectados</p>';
                }, 1500);
            }
        });
    }

    // Actualizar lista de IPs bloqueadas
    updateBlockedIPsList();
    
    // Actualizar cada 30 segundos
    setInterval(updateBlockedIPsList, 30000);
});

// Variables globales
let lastAlertTimestamp = '';
let realtimeInterval;
let retryAttempts = 0;
const MAX_RETRY_ATTEMPTS = 10;
const INITIAL_POLL_INTERVAL = 1000; // Reducir a 1 segundo para actualizaciones más frecuentes
let MIN_ALERT_TIMESTAMP = null; // Sin límite de tiempo por defecto
const ALERT_THRESHOLD = {
    HIGH: 5,     // Número de alertas por minuto para considerar alta severidad
    MEDIUM: 20,  // Número de alertas por minuto para considerar media severidad
    LOW: 50      // Número de alertas por minuto para considerar baja severidad
};
const RETRY_DELAY = 2000; // 2 segundos entre intentos

// Lista de IPs conocidas que no son amenazas
const KNOWN_SAFE_IPS = [
    '8.8.8.8',    // Google DNS
    '8.8.4.4',    // Google DNS
    '1.1.1.1',    // Cloudflare DNS
    '1.0.0.1',    // Cloudflare DNS
    '208.67.222.222', // OpenDNS
    '208.67.220.220'  // OpenDNS
];

// Estado de alertas por IP
const alertState = new Map();

// Función para verificar si una IP es interna
function isInternalIP(ip) {
    if (ip === '127.0.0.1') return true;
    
    // Verificar rangos de IPs internas
    const ipNum = ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
    
    // Verificar rango 10.0.0.0/8
    if ((ipNum & 0xFF000000) === 0x0A000000) return true;
    
    // Verificar rango 172.16.0.0/12
    if ((ipNum & 0xFFF00000) === 0xAC100000) return true;
    
    // Verificar rango 192.168.0.0/16
    if ((ipNum & 0xFFFF0000) === 0xC0A80000) return true;
    
    return false;
}

// Función para determinar la severidad de una alerta
function determineAlertSeverity(alert) {
    // Obtener la severidad directamente del servidor
    const severity = parseInt(alert.severity);
    
    // Mapear la severidad numérica a texto
    switch(severity) {
        case 3:
            return 'HIGH';
        case 2:
            return 'MEDIUM';
        case 1:
            return 'LOW';
        default:
            return 'LOW';
    }
}

// Función para verificar si una alerta es relevante
function isRelevantAlert(alert) {
    // Verificar si es tráfico interno
    const isInternal = isInternalIP(alert.source_ip);
    
    // Ignorar TODO el tráfico interno, incluyendo HTTP, SSH, etc.
    if (isInternal) {
        // Solo permitir tipos de alertas críticas específicas
        const criticalTypes = ['SYN Flood', 'ICMP Flood', 'UDP Flood', 'DDoS', 'DoS'];
        const isCritical = criticalTypes.some(type => 
            alert.alert_message && typeof alert.alert_message === 'string' && 
            alert.alert_message.toUpperCase().includes(type.toUpperCase())
        );
        
        if (!isCritical) {
            console.log(`Filtrando alerta interna: ${alert.alert_message || 'Tipo no especificado'} de ${alert.source_ip}`);
            return false;
        }
        
        // Marcar como crítica pero mantener la severidad original
        alert.is_critical = true;
        // No sobrescribir la severidad: mantener la que viene del servidor
        // alert.severity = 1; // Eliminado para mantener la severidad original
    }
    
    // Ignorar alertas muy antiguas
    if (alert.timestamp < MIN_ALERT_TIMESTAMP) return false;
    
    return true;
}

// Cache local para reducir tráfico
let alertCache = new Map();
const CACHE_MAX_SIZE = 100;

// Estado de las notificaciones
let notificationState = {
    enabled: true,
    lastSummarySent: null
};

// Configuración de notificaciones
const NOTIFICATION_CONFIG = {
    TIME_WINDOW: 5 * 60 * 1000, // 5 minutos
    RETENTION_TIME: 30 * 60 * 1000, // 30 minutos
    SOUND_VOLUME: {
        HIGH: 0.8,
        MEDIUM: 0.6,
        LOW: 0.4
    }
};

// Estado del sistema de notificaciones
let notificationSystem = {
    lastGroupedAlert: null,
    groupedAlerts: new Map(),
    soundPlayers: new Map()
};

// Configuración de sonidos
const SOUND_CONFIG = {
    HIGH: {
        src: 'sounds/alert_high.mp3',
        volume: 0.8
    },
    MEDIUM: {
        src: 'sounds/alert_medium.mp3',
        volume: 0.6
    },
    LOW: {
        src: 'sounds/alert_low.mp3',
        volume: 0.4
    }
};

// Configuración de resumen diario
const DAILY_SUMMARY = {
    ENABLED: true,
    TIME: '18:00', // Hora del resumen diario
    INCLUDE_STATS: true,
    INCLUDE_TOP_ATTACKERS: true
};
function updateAlertCache(alerts) {
    alerts.forEach(alert => {
        alertCache.set(alert.id, alert);
        
        // Mantener tamaño del cache
        if (alertCache.size > CACHE_MAX_SIZE) {
            const oldest = Array.from(alertCache.keys())[0];
            alertCache.delete(oldest);
        }
    });
}

// Función para actualizar estadísticas del dashboard
function updateDashboardStats(stats) {
    // Actualizar contadores de estadísticas si existen en la página
    const elements = {
        'total_alerts': document.querySelector('.stat-card:nth-child(1) .stat-number'),
        'high_severity': document.querySelector('.stat-card:nth-child(2) .stat-number'),
        'blocked_ips': document.querySelector('.stat-card:nth-child(3) .stat-number'),
    };
    
    // Actualizar cada elemento si existe
    for (const [key, element] of Object.entries(elements)) {
        if (element && stats[key] !== undefined) {
            element.textContent = stats[key];
        }
    }
    
    // Actualizar tendencias
    const recentTrend = document.querySelector('.stat-card:nth-child(1) .stat-trend');
    if (recentTrend && stats.recent_alerts !== undefined) {
        recentTrend.innerHTML = `
            <i class="fas fa-${stats.recent_alerts > 0 ? 'arrow-up' : 'arrow-down'}"></i>
            ${stats.recent_alerts} in last 24h
        `;
        recentTrend.className = `stat-trend ${stats.recent_alerts > 0 ? 'up' : 'down'}`;
    }
}

// Función para verificar nuevas alertas
function checkForNewAlerts() {
    console.log('Verificando nuevas alertas...');
    
    // Realizar petición AJAX para verificar nuevas alertas
    fetch(`api/check-alerts.php?last_timestamp=${encodeURIComponent(lastAlertTimestamp)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`Error HTTP: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            retryAttempts = 0; // Resetear intentos fallidos
            
            console.log('Respuesta del servidor:', data);
            
            if (data.has_new_alerts && data.alerts && data.alerts.length > 0) {
                console.log(`Se encontraron ${data.alerts.length} nuevas alertas`);
                
                // Actualizar el último timestamp conocido
                if (data.latest_timestamp) {
                    lastAlertTimestamp = data.latest_timestamp;
                    console.log('Nuevo timestamp de última alerta:', lastAlertTimestamp);
                }
                
                // Procesar cada nueva alerta
                data.alerts.forEach(alert => {
                    try {
                        console.log('Procesando alerta:', alert);
                        if (isRelevantAlert(alert)) {
                            console.log('Alerta relevante, actualizando UI...');
                            updateAlertUI(alert);
                        } else {
                            console.log('Alerta filtrada por reglas de relevancia');
                        }
                    } catch (error) {
                        console.error('Error al procesar alerta:', error, alert);
                    }
                });
                
                // Actualizar estadísticas del dashboard
                if (data.stats) {
                    console.log('Actualizando estadísticas:', data.stats);
                    updateDashboardStats(data.stats);
                }
            } else {
                console.log('No hay nuevas alertas');
                if (data.latest_timestamp) {
                    lastAlertTimestamp = data.latest_timestamp;
                    console.log('Actualizado timestamp de última alerta:', lastAlertTimestamp);
                }
            }
        })
        .catch(error => {
            console.error('Error al verificar nuevas alertas:', error);
            
            // Reintentar con retroceso exponencial
            retryAttempts++;
            if (retryAttempts <= MAX_RETRY_ATTEMPTS) {
                const delay = Math.min(1000 * Math.pow(2, retryAttempts), 30000); // Hasta 30 segundos
                console.log(`Reintentando en ${delay}ms... (Intento ${retryAttempts}/${MAX_RETRY_ATTEMPTS})`);
                setTimeout(checkForNewAlerts, delay);
            } else {
                console.error('Se agotaron los intentos de reconexión');
                // Intentar de nuevo después de un tiempo más largo
                setTimeout(() => {
                    console.log('Reiniciando verificación de alertas...');
                    retryAttempts = 0;
                    checkForNewAlerts();
                }, 60000); // Esperar 1 minuto antes de reintentar
            }
        });
}

function formatTimestamp(timestamp) {
    // Espera formato ISO o Y-m-d H:i:s
    const date = new Date(timestamp.replace(' ', 'T'));
    if (isNaN(date)) return timestamp;
    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const aaaa = date.getFullYear();
    const hh = String(date.getHours()).padStart(2, '0');
    const min = String(date.getMinutes()).padStart(2, '0');
    return `${dd}-${mm}-${aaaa} ${hh}:${min}`;
}

// Ver detalles de alerta (redirigir a la página de detalles)
function viewAlertDetails(alertId) {
    window.location.href = `alert-details.php?id=${alertId}`;
}

// Bloquear IP (enviar solicitud al backend)
function blockIP(ip) {
    if (!ip || typeof ip !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$|^([a-fA-F0-9:]+)$/.test(ip)) {
        alert('IP inválida. No se puede bloquear.');
        return;
    }
    if (confirm(`¿Estás seguro de que deseas bloquear la IP ${ip}?`)) {
        fetch('api/block-ip.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent('Bloqueo manual desde alertas')}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`IP ${ip} bloqueada exitosamente`);
                window.location.reload();
            } else {
                alert(`Error al bloquear IP: ${data.message || 'Desconocido'}`);
                if (data.details) console.error(data.details);
            }
        })
        .catch(error => {
            console.error('Error blocking IP:', error);
            alert('Error al bloquear IP. Consulta la consola para más detalles.');
        });
    }
}

// Función para actualizar la lista de IPs bloqueadas
function updateBlockedIPsList() {
    fetch('api/blocked-ips.php')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const blockedIPsTable = document.querySelector('.blocked-ips-table tbody');
                if (blockedIPsTable) {
                    blockedIPsTable.innerHTML = '';
                    data.blocked_ips.forEach(ip => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${ip.ip_address}</td>
                            <td>${formatTimestamp(ip.timestamp)}</td>
                            <td>${ip.reason}</td>
                            <td>
                                <button class="action-btn unblock-button" onclick="unblockIP('${ip.ip_address}')">
                                    <i class="fas fa-unlock"></i> Desbloquear
                                </button>
                            </td>
                        `;
                        blockedIPsTable.appendChild(row);
                    });
                }
            }
        })
        .catch(error => {
            console.error('Error al obtener lista de IPs bloqueadas:', error);
        });
}

// Función para desbloquear IP
function unblockIP(ip) {
    if (!ip || typeof ip !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$|^([a-fA-F0-9:]+)$/.test(ip)) {
        alert('IP inválida. No se puede desbloquear.');
        return;
    }
    
    if (confirm(`¿Estás seguro de que deseas desbloquear la IP ${ip}?`)) {
        fetch('api/unblock-ip.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip_address: ip })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`IP ${ip} desbloqueada exitosamente`);
                // Actualizar la interfaz
                updateBlockedIPsList();
                // Actualizar contadores
                const blockedIpsCounter = document.getElementById('blocked-ips');
                if (blockedIpsCounter) {
                    blockedIpsCounter.textContent = 
                        Math.max(0, (parseInt(blockedIpsCounter.textContent) || 0) - 1);
                }
            } else {
                alert(`Error al desbloquear IP: ${data.message || 'Desconocido'}`);
                if (data.details) console.error(data.details);
            }
        })
        .catch(error => {
            console.error('Error unblocking IP:', error);
            alert('Error al desbloquear IP. Consulta la consola para más detalles.');
        });
    }
}

// Función mejorada para actualizar la UI de alertas
function updateAlertUI(alert) {
    const alertsTable = document.querySelector('.alerts-table tbody');
    if (!alertsTable) return;
    
    const row = document.createElement('tr');
    const severity = determineAlertSeverity(alert);
    row.innerHTML = `
        <td>${alert.id}</td>
        <td>${formatTimestamp(alert.timestamp)}</td>
        <td>${alert.source_ip}</td>
        <td>${alert.destination_ip || ''}</td>
        <td>${alert.alert_message}</td>
        <td>${alert.protocol || 'unknown'}</td>
        <td class="severity ${severity.toLowerCase()}">${severity}</td>
        <td>${alert.action_taken || 'none'}</td>
        <td>
            <button class="action-btn alerta details-button" onclick="viewAlertDetails(${alert.id})">
                <i class="fas fa-eye"></i>
            </button>
            ${alert.action_taken && alert.action_taken.includes('Blocked') ? 
                `<button class="action-btn alerta unblock-button" onclick="unblockIP('${alert.source_ip}')">
                    <i class="fas fa-unlock"></i>
                </button>` :
                `<button class="action-btn alerta block-button" onclick="blockIP('${alert.source_ip}')">
                    <i class="fas fa-ban"></i>
                </button>`
            }
        </td>
    `;
    
    alertsTable.insertBefore(row, alertsTable.firstChild);
    
    // Actualizar contadores
    updateAlertCounters(alert);
}

// Función para actualizar contadores de alertas
function updateAlertCounters(alert) {
    const counters = {
        'total-alerts': document.getElementById('total-alerts'),
        'high-severity': document.getElementById('high-severity'),
        'blocked-ips': document.getElementById('blocked-ips'),
        'recent-alerts': document.getElementById('recent-alerts')
    };
    
    if (counters['total-alerts']) {
        counters['total-alerts'].textContent = 
            (parseInt(counters['total-alerts'].textContent) || 0) + 1;
    }
    
    if (alert.severity === 3 && counters['high-severity']) {
        counters['high-severity'].textContent = 
            (parseInt(counters['high-severity'].textContent) || 0) + 1;
    }
    
    if (alert.action_taken && alert.action_taken.includes('Blocked') && counters['blocked-ips']) {
        counters['blocked-ips'].textContent = 
            (parseInt(counters['blocked-ips'].textContent) || 0) + 1;
    }
    
    if (counters['recent-alerts']) {
        counters['recent-alerts'].textContent = 
            (parseInt(counters['recent-alerts'].textContent) || 0) + 1;
    }
}

// Función para desbloquear IP
function unblockIP(ip) {
    if (!ip || typeof ip !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$|^([a-fA-F0-9:]+)$/.test(ip)) {
        alert('IP inválida. No se puede desbloquear.');
        return;
    }
    
    if (confirm(`¿Estás seguro de que deseas desbloquear la IP ${ip}?`)) {
        fetch('api/unblock-ip.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip_address: ip })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`IP ${ip} desbloqueada exitosamente`);
                // Actualizar la interfaz
                updateBlockedIPsList();
                // Actualizar contadores
                const blockedIpsCounter = document.getElementById('blocked-ips');
                if (blockedIpsCounter) {
                    blockedIpsCounter.textContent = 
                        Math.max(0, (parseInt(blockedIpsCounter.textContent) || 0) - 1);
                }
            } else {
                alert(`Error al desbloquear IP: ${data.message || 'Desconocido'}`);
                if (data.details) console.error(data.details);
            }
        })
        .catch(error => {
            console.error('Error unblocking IP:', error);
            alert('Error al desbloquear IP. Consulta la consola para más detalles.');
        });
    }
}

// Función para actualizar la lista de IPs bloqueadas
function updateBlockedIPsList() {
    fetch('api/blocked-ips.php')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const blockedIPsTable = document.querySelector('.blocked-ips-table tbody');
                if (blockedIPsTable) {
                    blockedIPsTable.innerHTML = '';
                    data.blocked_ips.forEach(ip => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${ip.ip_address}</td>
                            <td>${formatTimestamp(ip.timestamp)}</td>
                            <td>${ip.reason}</td>
                            <td>
                                <button class="action-btn unblock-button" onclick="unblockIP('${ip.ip_address}')">
                                    <i class="fas fa-unlock"></i> Desbloquear
                                </button>
                            </td>
                        `;
                        blockedIPsTable.appendChild(row);
                    });
                }
            }
        })
        .catch(error => {
            console.error('Error al obtener lista de IPs bloqueadas:', error);
        });
}
