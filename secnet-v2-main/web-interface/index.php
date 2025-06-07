<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="assets/logo.png">
    <title>SecNet</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<!-- Tipografía tecnológica para títulos -->
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <!-- Componente de notificación de alertas en tiempo real -->
        <div id="alertNotifications" class="alert-notifications"></div>
        
        <header>
            <div class="logo-container">
                <a href="index.php" style="display:flex;align-items:center;text-decoration:none;">
                    <img src="assets/logo.png" alt="Logo">
                    <h1 style="font-family: 'Orbitron', sans-serif;">SecNet</h1>
                </a>
            </div>
            <nav>
                <ul>
                    <li><a href="index.php" class="active"><i class="fas fa-tachometer-alt"></i> Panel</a></li>
                    <li><a href="alerts.php"><i class="fas fa-exclamation-triangle"></i> Alertas</a></li>
                </ul>
            </nav>
        </header>
        
        <main>
            <div class="dashboard-header">
                <h2><i class="fas fa-chart-line"></i> Resumen de Seguridad</h2>
            </div>
            <section class="dashboard">
                <div class="stats-container">
                    <?php
                    // Connect to SQLite database
                    $db = new SQLite3('/var/www/html/database/alerts.db');
                    
                    // Obtener IPs bloqueadas
                    $blocked_ip_list = [];
                    $blocked_result = $db->query("SELECT DISTINCT ip_address FROM blocked_ips");
                    while ($row = $blocked_result->fetchArray(SQLITE3_ASSOC)) {
                        $blocked_ip_list[] = $row['ip_address'];
                    }
                    $has_blocked = count($blocked_ip_list) > 0;
                    $blocked_ips_placeholder = $has_blocked ? "'" . implode("','", $blocked_ip_list) . "'" : '';

                    // Generar condiciones dinámicamente
                    // DESACTIVAMOS EL FILTRO PARA MOSTRAR TODA LA INFORMACIÓN
                    $where_not_blocked = "1=1";

                    // Obtener el rango de tiempo seleccionado
                    $timeRange = isset($_GET['timeRange']) ? $_GET['timeRange'] : '';
                    $useTimeFilter = ($timeRange !== '' && is_numeric($timeRange));
                    $timeFilter = $useTimeFilter ? "timestamp > datetime('now', '-$timeRange hours')" : '1=1';

                    // Get alert statistics
                    $total_alerts = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE $where_not_blocked AND $timeFilter");
                    $high_severity = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE severity >= 2 AND ($where_not_blocked) AND $timeFilter");
                    $blocked_ips = $db->querySingle("SELECT COUNT(DISTINCT ip_address) FROM blocked_ips");
                    // Contar alertas de las últimas 24 horas independientemente del filtro de tiempo seleccionado
                    $recent_alerts = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', '-24 hours') AND ($where_not_blocked)");

                    // Get alert types for chart data
                    $alert_types = [];
                    $query = "SELECT alert_message, COUNT(*) as count FROM alerts WHERE $where_not_blocked AND $timeFilter GROUP BY alert_message ORDER BY count DESC LIMIT 5";
                    $alert_types_result = $db->query($query);
                    while ($row = $alert_types_result->fetchArray(SQLITE3_ASSOC)) {
                        $alert_types[$row['alert_message']] = $row['count'];
                    }

                    // Get alerts by hour for timeline chart
                    $alerts_by_hour = [];
                    $timeline_query = "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as count FROM alerts WHERE $timeFilter AND ($where_not_blocked) GROUP BY hour ORDER BY hour";
                    $timeline_result = $db->query($timeline_query);
                    while ($row = $timeline_result->fetchArray(SQLITE3_ASSOC)) {
                        $alerts_by_hour[$row['hour']] = $row['count'];
                    }

                    // Get severity distribution
                    $severity_dist = [];
                    $severity_query = "SELECT severity, COUNT(*) as count FROM alerts WHERE $where_not_blocked AND $timeFilter GROUP BY severity ORDER BY severity";
                    $severity_result = $db->query($severity_query);
                    while ($row = $severity_result->fetchArray(SQLITE3_ASSOC)) {
                        $severity_dist[$row['severity']] = $row['count'];
                    }

                    // Get blocked IPs with their details
                    $blocked_ips_list = [];
                    $blocked_ips_query = "SELECT b.ip_address, b.timestamp, b.reason, 
                                         (SELECT COUNT(*) FROM alerts WHERE source_ip = b.ip_address) as alert_count,
                                         (SELECT MAX(severity) FROM alerts WHERE source_ip = b.ip_address) as max_severity
                                         FROM blocked_ips b
                                         ORDER BY b.timestamp DESC LIMIT 10";
                    $blocked_ips_result = $db->query($blocked_ips_query);
                    while ($row = $blocked_ips_result->fetchArray(SQLITE3_ASSOC)) {
                        $blocked_ips_list[$row['ip_address']] = [
                            'timestamp' => $row['timestamp'],
                            'reason' => $row['reason'],
                            'alert_count' => $row['alert_count'],
                            'max_severity' => $row['max_severity'] ?: 0,
                            'is_blocked' => true
                        ];
                    }
                    ?>
                    
                    <div class="stat-card">
                        <div class="stat-icon"><i class="fas fa-exclamation-circle"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">Alertas Totales</div>
                            <div class="stat-value"><?php echo $total_alerts; ?></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon danger"><i class="fas fa-bolt"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">Alta Gravedad</div>
                            <div class="stat-value"><?php echo $high_severity; ?></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon"><i class="fas fa-ban"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">IPs Bloqueadas</div>
                            <div class="stat-value"><?php echo $blocked_ips; ?></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon"><i class="fas fa-clock"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">Alertas últimas 24h</div>
                            <div class="stat-value"><?php echo $recent_alerts; ?></div>
                        </div>
                    </div>
                </div>
                <div class="charts-container">
<?php
// Preparar datos para gráficos
function prepareChartDatasets() {
    $db = new SQLite3('/var/www/html/database/alerts.db');
    
    // Obtener tipos de alertas
    $alert_types = [];
    $query = "SELECT alert_message, COUNT(*) as count FROM alerts GROUP BY alert_message ORDER BY count DESC LIMIT 5";
    $alert_types_result = $db->query($query);
    while ($row = $alert_types_result->fetchArray(SQLITE3_ASSOC)) {
        $alert_types[$row['alert_message']] = $row['count'];
    }
    
    // Obtener distribución de gravedad
    $severity_dist = [];
    $severity_query = "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY severity";
    $severity_result = $db->query($severity_query);
    while ($row = $severity_result->fetchArray(SQLITE3_ASSOC)) {
        $severity_dist[$row['severity']] = $row['count'];
    }
    
    // Obtener alertas por hora
    $alerts_by_hour = [];
    $timeline_query = "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as count FROM alerts GROUP BY hour ORDER BY hour";
    $timeline_result = $db->query($timeline_query);
    while ($row = $timeline_result->fetchArray(SQLITE3_ASSOC)) {
        $alerts_by_hour[$row['hour']] = $row['count'];
    }
    
    return [
        'alert_types' => $alert_types,
        'severity_dist' => $severity_dist,
        'alerts_by_hour' => $alerts_by_hour
    ];
}

$chartData = prepareChartDatasets();
?>

                    <div class="chart-card">
                        <h3><i class="fas fa-chart-pie"></i> Tipos de Alertas</h3>
                        <div class="chart-container" style="min-height: 300px;">
                            <canvas id="alertTypesChart"></canvas>
                        </div>
                    </div>
                    <div class="chart-card">
                        <h3><i class="fas fa-chart-bar"></i> Distribución de gravedad</h3>
                        <div class="chart-container" style="min-height: 300px;">
                            <canvas id="severityChart" style="width: 100%; height: 100%;"></canvas>
                        </div>
                    </div>
                </div>
                <section class="blocked-ips-section">
                    <div class="section-header">
                        <h3><i class="fas fa-lock"></i> IPs Bloqueadas</h3>
                    </div>
                    <div class="table-container">
                        <table>
                            <colgroup>
                                <col style="width: 180px;">
                                <col style="width: 160px;">
                                <col style="width: 100px;">
                                <col style="width: 120px;">
                                <col style="min-width: 200px;">
                                <col style="width: 130px;">
                            </colgroup>
                            <thead>
                                <tr>
                                    <th>Dirección IP</th>
                                    <th>Fecha de Bloqueo</th>
                                    <th>Alertas</th>
                                    <th>Gravedad</th>
                                    <th>Razón</th>
                                    <th>Estado</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($blocked_ips_list)): ?>
                                    <tr>
                                        <td colspan="6" class="no-data">
                                            <i class="fas fa-info-circle"></i>
                                            <span>No hay direcciones IP bloqueadas actualmente</span>
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php 
                                    $currentDate = new DateTime('now', new DateTimeZone('UTC'));
                                    foreach ($blocked_ips_list as $ip => $info): 
                                        $date = new DateTime($info['timestamp'], new DateTimeZone('UTC'));
                                        $date->setTimezone(new DateTimeZone('Europe/Madrid'));
                                        $formattedDate = $date->format('d-m-Y H:i');
                                        $isRecent = ($currentDate->getTimestamp() - $date->getTimestamp()) < 3600; // Menos de 1 hora
                                    ?>
                                        <tr>
                                            <td>
                                                <div class="ip-address">
                                                    <i class="fas fa-lock"></i>
                                                    <span><?php echo htmlspecialchars($ip); ?></span>
                                                    <?php if ($isRecent): ?>
                                                        <span class="new-badge" title="Bloqueada recientemente">Nuevo</span>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                            <td class="timestamp" title="<?php echo $formattedDate; ?>">
                                                <?php echo $formattedDate; ?>
                                            </td>
                                            <td class="text-center">
                                                <span class="alert-count"><?php echo $info['alert_count']; ?></span>
                                            </td>
                                            <td class="text-center">
                                                <span class="gravedad-badge gravedad-<?php echo $info['max_severity'] ?: 1; ?>">
                                                    <?php 
                                                    $severityText = ['Baja', 'Media', 'Alta'];
                                                    $severityNum = (int)$info['max_severity'] - 1;
                                                    echo $severityText[$severityNum] ?? 'N/A'; 
                                                    ?>
                                                </span>
                                            </td>
                                            <td class="reason" title="<?php 
                                                $reason = $info['reason'] ?: 'Sin especificar';
                                                $reason = preg_replace('/\s*\[Actividad de red normal\]$/', '', $reason);
                                                echo htmlspecialchars($reason); 
                                            ?>">
                                                <?php 
                                                    $reason = $info['reason'] ?: 'Sin especificar';
                                                    $reason = preg_replace('/\s*\[Actividad de red normal\]$/', '', $reason);
                                                    echo htmlspecialchars($reason); 
                                                ?>
                                            </td>
                                            <td class="text-center">
                                                <span class="status-badge blocked">
                                                    <i class="fas fa-shield-alt"></i>
                                                    Bloqueada
                                                </span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </section>
                <div class="recent-alerts">
                    <div class="section-header">
                        <h3><i class="fas fa-bell"></i> Alertas recientes <a href="alerts.php" class="view-all"><i class="fas fa-arrow-right"></i></a></h3>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Hora</th>
                                    <th>IP origen</th>
                                    <th>Alertas</th>
                                    <th>Gravedad máx.</th>
                                    <th>Acción</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                // Get recent alerts (limit to 5 most recent)
                                $results = $db->query("SELECT * FROM alerts WHERE $where_not_blocked ORDER BY timestamp DESC LIMIT 5");
                                
                                while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                                    // Convert UTC timestamp to Madrid timezone
                                    $date = new DateTime($row['timestamp'], new DateTimeZone('UTC'));
                                    $date->setTimezone(new DateTimeZone('Europe/Madrid'));
                                    $formattedDate = $date->format('d-m-Y H:i');
                                    
                                    echo '<tr>';
                                    echo '<td>' . htmlspecialchars($formattedDate) . '</td>';
                                    echo '<td>' . htmlspecialchars($row['source_ip']) . '</td>';
                                    echo '<td>' . htmlspecialchars($row['alert_message']) . '</td>';
                                    echo '<td><span class="gravedad-badge gravedad-' . (int)$row['severity'] . '">' . htmlspecialchars($row['severity']) . '</span></td>';
                                    echo '<td><a href="alert-details.php?id=' . urlencode($row['id']) . '" class="btn btn-icon" title="Ver detalles"><i class="fas fa-eye"></i></a></td>';
                                    echo '</tr>';
                                }
                                
                                $db->close();
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>
        </main>
        
        <footer class="footer-container">
            <p>&copy; <?php echo date('Y'); ?> Sistema Automatizado de Respuesta a Incidentes</p>
        </footer>
    </div>
    
    <script>
    // Datos para los gráficos - Hacerlos globales
    window.alertTypesData = {
        labels: <?php echo json_encode(array_keys($alert_types)); ?>,
        data: <?php echo json_encode(array_values($alert_types)); ?>
    };
    
    window.timelineData = {
        labels: <?php echo json_encode(array_keys($alerts_by_hour)); ?>,
        data: <?php echo json_encode(array_values($alerts_by_hour)); ?>
    };
    
    // Preparar etiquetas de gravedad
    window.severityLabels = <?php 
        $severityNames = ['Baja (1)', 'Media (2)', 'Alta (3)'];
        $formattedLabels = [];
        // Asegurarse de que tengamos entradas para las gravedades 1, 2 y 3
        for ($i = 1; $i <= 3; $i++) {
            $formattedLabels[] = $severityNames[$i-1] ?? "Gravedad $i";
        }
        echo json_encode($formattedLabels);
    ?>;
    
    // Asegurarse de que los datos de gravedad tengan 3 valores (para 1, 2, 3)
    window.severityData = {
        labels: window.severityLabels,
        data: <?php 
            $severityValues = [0, 0, 0]; // Inicializar con ceros para gravedad 1, 2, 3
            foreach ($severity_dist as $severity => $count) {
                $sevNum = intval($severity) - 1; // Convertir a índice 0-2
                if ($sevNum >= 0 && $sevNum <= 2) {
                    $severityValues[$sevNum] = $count;
                }
            }
            echo json_encode($severityValues);
        ?>
    };
    
    // Debug: mostrar datos en consola
    console.log('alertTypesData:', window.alertTypesData);
    console.log('severityData:', window.severityData);
    
    <?php
    $last_alert_row = $db = new SQLite3('/var/www/html/database/alerts.db');
    $last_alert_row = $last_alert_row->querySingle("SELECT timestamp FROM alerts ORDER BY timestamp DESC LIMIT 1");
    if ($last_alert_row) {
        echo "let lastAlertTimestamp = '" . $last_alert_row . "';\n";
    } else {
        echo "let lastAlertTimestamp = '2000-01-01 00:00:00';\n";
    }
    ?>
    </script>
    <script src="/js/main.clean.js"></script>
    <script>
        // Función para mostrar notificación
        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = `alert-notification ${type}`;
            notification.textContent = message;
            document.getElementById('alertNotifications').appendChild(notification);
            
            // Eliminar la notificación después de 5 segundos
            setTimeout(() => {
                notification.remove();
            }, 5000);
        }

        // Manejar el clic en el botón de desbloquear IP
        document.addEventListener('click', async function(e) {
            if (e.target.closest('.unblock-ip') || e.target.classList.contains('fa-unlock')) {
                const button = e.target.closest('.unblock-ip') || e.target.closest('button');
                const ip = button.dataset.ip;
                const row = button.closest('tr');
                
                if (!ip) return;
                
                // Mostrar confirmación
                if (!confirm(`¿Estás seguro de que deseas desbloquear la IP ${ip}?`)) {
                    return;
                }
                
                // Deshabilitar el botón mientras se procesa la solicitud
                button.disabled = true;
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Procesando...';
                
                try {
                    const response = await fetch('/api/unblock-ip.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ ip: ip })
                    });
                    
                    const result = await response.json();
                    
                    if (!response.ok) {
                        throw new Error(result.message || 'Error en la respuesta del servidor');
                    }
                    
                    if (result.success) {
                        showNotification(`IP ${ip} desbloqueada correctamente`, 'success');
                        
                        // Actualizar la interfaz sin recargar la página
                        if (row) {
                            // Actualizar el estado a "Activa"
                            const statusCell = row.querySelector('td:nth-child(4)');
                            if (statusCell) {
                                statusCell.innerHTML = '<span class="status-badge">Activa</span>';
                            }
                            
                            // Actualizar el icono de bloqueo
                            const lockIcon = row.querySelector('.fa-lock');
                            if (lockIcon) {
                                lockIcon.remove();
                            }
                            
                            // Actualizar el botón de acciones
                            const actionsCell = row.querySelector('.actions-cell');
                            if (actionsCell) {
                                actionsCell.innerHTML = '<span class="text-muted">-</span>';
                            }
                        } else {
                            // Si no podemos actualizar la interfaz, recargar la página
                            setTimeout(() => window.location.reload(), 1000);
                        }
                    } else {
                        throw new Error(result.message || 'Error al desbloquear la IP');
                    }
                } catch (error) {
                    console.error('Error al desbloquear la IP:', error);
                    showNotification(`Error al desbloquear la IP: ${error.message}`, 'error');
                    button.disabled = false;
                    button.innerHTML = '<i class="fas fa-unlock"></i> DESBLOQUEAR IP';
                }
            }
        });
        
        // Inicializar los gráficos cuando el DOM esté completamente cargado
        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM completamente cargado, inicializando gráficos...');
            // Verificar si Chart.js está cargado
            if (typeof Chart === 'undefined') {
                console.error('Chart.js no se ha cargado correctamente');
                return;
            }
            // Verificar si la función initCharts existe
            if (typeof initCharts === 'function') {
                console.log('Inicializando gráficos...');
                initCharts();
            } else {
                console.error('La función initCharts no está definida');
            }
        });
    </script>
</body>
</html>
