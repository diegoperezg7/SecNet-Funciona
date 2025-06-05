<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alertas - Sistema de Respuesta a Incidentes de Seguridad</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-container">
                <a href="index.php" style="display:flex;align-items:center;text-decoration:none;">
                    <img src="assets/logo.png" alt="Logo">
                    <h1 style="font-family: 'Orbitron', sans-serif;">SecNet</h1>
                </a>
            </div>
            <nav>
                <ul>
                    <li><a href="index.php"><i class="fas fa-tachometer-alt"></i> Panel</a></li>
                    <li><a href="alerts.php" class="active"><i class="fas fa-exclamation-triangle"></i> Alertas</a></li>
                </ul>
            </nav>
        </header>
        <main>
            <section class="alerts-section">
                <!-- Botón para mostrar/ocultar filtros -->
                <button id="toggleFiltersBtn" class="filter-button" type="button" style="margin-bottom:1.2rem;"><i class="fas fa-sliders-h"></i> Filtrar</button>
                <div class="filters" id="filtersPanel" style="display:none;">
                    <form method="get" action="alerts.php">
                        <div class="filter-group">
                            <label for="severity">Severidad:</label>
                            <select name="severity" id="severity">
                                <option value="">Todas</option>
                                <option value="1" <?php echo isset($_GET['severity']) && $_GET['severity'] == '1' ? 'selected' : ''; ?>>Baja (1)</option>
                                <option value="2" <?php echo isset($_GET['severity']) && $_GET['severity'] == '2' ? 'selected' : ''; ?>>Alta (2+)</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label for="ip">Dirección IP:</label>
                            <input type="text" name="ip" id="ip" value="<?php echo isset($_GET['ip']) ? htmlspecialchars($_GET['ip']) : ''; ?>">
                        </div>
                        <div class="filter-group">
                            <label for="timeframe">Periodo:</label>
                            <select name="timeframe" id="timeframe">
                                <option value="">Todo el tiempo</option>
                                <option value="24" <?php echo isset($_GET['timeframe']) && $_GET['timeframe'] == '24' ? 'selected' : ''; ?>>Últimas 24 horas</option>
                                <option value="48" <?php echo isset($_GET['timeframe']) && $_GET['timeframe'] == '48' ? 'selected' : ''; ?>>Últimas 48 horas</option>
                                <option value="168" <?php echo isset($_GET['timeframe']) && $_GET['timeframe'] == '168' ? 'selected' : ''; ?>>Última semana</option>
                                <option value="720" <?php echo isset($_GET['timeframe']) && $_GET['timeframe'] == '720' ? 'selected' : ''; ?>>Últimos 30 días</option>
                            </select>
                        </div>
                        <button type="submit" class="filter-button"><i class="fas fa-filter"></i> Aplicar filtros</button>
                        <a href="alerts.php" class="filter-button secondary"><i class="fas fa-sync-alt"></i> Refrescar</a>
                    </form>
                </div>
                <div class="alerts-table">
                    <table class="tech-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Fecha/Hora</th>
                                <th>IP Origen</th>
                                <th>IP Destino</th>
                                <th>Alerta</th>
                                <th>Protocolo</th>
                                <th>Severidad</th>
                                <th>Operaciones</th>
                            </tr>
                        </thead>
                        <tbody id="alertsTableBody">
                            <?php
                            $db = new SQLite3('/var/www/html/database/alerts.db');
                            // Configurar zona horaria para SQLite
                            $db->exec("PRAGMA timezone = 'Europe/Madris'");
                            
                            // Obtener el offset para la paginación
                            $offset = isset($_GET['offset']) ? intval($_GET['offset']) : 0;
                            $limit = 30; // Número de alertas por página
                            
                            $query = "SELECT * FROM alerts WHERE 1=1";
                            $countQuery = "SELECT COUNT(*) as total FROM alerts WHERE 1=1";
                            $params = [];
                            
                            if (isset($_GET['severity']) && $_GET['severity'] !== '') {
                                if ($_GET['severity'] == '1') {
                                    $query .= " AND severity = 1";
                                    $countQuery .= " AND severity = 1";
                                } else {
                                    $query .= " AND severity >= 2";
                                    $countQuery .= " AND severity >= 2";
                                }
                            }
                            if (isset($_GET['ip']) && $_GET['ip'] !== '') {
                                $ip = $_GET['ip'];
                                $query .= " AND (source_ip LIKE :ip OR destination_ip LIKE :ip)";
                                $countQuery .= " AND (source_ip LIKE :ip OR destination_ip LIKE :ip)";
                                $params[':ip'] = "%$ip%";
                            }
                            if (isset($_GET['timeframe']) && $_GET['timeframe'] !== '') {
                                $hours = intval($_GET['timeframe']);
                                $timeCondition = " AND timestamp > datetime('now', '-$hours hours', 'localtime')";
                                $query .= $timeCondition;
                                $countQuery .= $timeCondition;
                                // Convertir a timestamp Unix para el frontend
                                $timeLimit = strtotime("-$hours hours");
                                $MIN_ALERT_TIMESTAMP = $timeLimit;
                            } else {
                                // Si no hay filtro de tiempo, no aplicar límite
                                $MIN_ALERT_TIMESTAMP = null;
                            }
                            
                            // Obtener el total de alertas
                            $stmt = $db->prepare($countQuery);
                            foreach ($params as $key => $value) {
                                $stmt->bindValue($key, $value, SQLITE3_TEXT);
                            }
                            $totalAlerts = $stmt->execute()->fetchArray(SQLITE3_ASSOC)['total'];
                            
                            // Aplicar ordenación y límites
                            $query .= " ORDER BY timestamp DESC LIMIT $limit OFFSET $offset";
                            
                            $stmt = $db->prepare($query);
                            foreach ($params as $key => $value) {
                                $stmt->bindValue($key, $value, SQLITE3_TEXT);
                            }
                            $results = $stmt->execute();
                            $alertCount = 0;
                            
                            while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                                $alertCount++;
                                // Asignar clases de severidad según la escala:
                                // 3: Alta, 2: Media, 1: Baja
                                $severity_class = 'low';
                                if ($row['severity'] == 2) {
                                    $severity_class = 'medium';
                                } elseif ($row['severity'] >= 3) {
                                    $severity_class = 'high';
                                }
                                echo '<tr>';
                                echo '<td>' . $row['id'] . '</td>';
                                // Convertir la fecha/hora a la zona horaria de Madrid
                                $date = new DateTime($row['timestamp'], new DateTimeZone('UTC'));
                                $date->setTimezone(new DateTimeZone('Europe/Madrid'));
                                echo '<td data-timestamp="' . strtotime($row['timestamp']) . '">' . $date->format('d-m-Y H:i') . '</td>';
                                echo '<td>' . htmlspecialchars($row['source_ip']) . '</td>';
                                echo '<td>' . htmlspecialchars($row['destination_ip']) . '</td>';
                                echo '<td>' . htmlspecialchars($row['alert_message']) . '</td>';
                                echo '<td>' . htmlspecialchars($row['protocol']) . '</td>';
                                echo '<td class="severity ' . $severity_class . '">' . $row['severity'] . '</td>';
                                echo '<td>';
                                echo '<button class="action-btn alerta details-button" onclick="viewAlertDetails(' . $row['id'] . ')"><i class="fas fa-eye"></i></button> ';
                                echo '<button class="action-btn alerta block-button" onclick="blockIP(\'' . htmlspecialchars($row['source_ip']) . '\')"><i class="fas fa-ban"></i></button>';
                                echo '</td>';
                                echo '</tr>';
                            }
                            $db->close();
                            
                            // Guardar el último timestamp para la paginación
                            $hasMoreAlerts = ($offset + $alertCount) < $totalAlerts;
                            ?>
                        </tbody>
                    </table>
                    <?php if ($hasMoreAlerts): ?>
                    <div class="load-more-container">
                        <button id="loadMoreBtn" class="load-more-btn" data-offset="<?php echo $offset + $limit; ?>">
                            <i class="fas fa-arrow-down"></i> Ver más alertas
                        </button>
                        <div id="loadingIndicator" class="loading-indicator" style="display: none;">
                            <i class="fas fa-spinner fa-spin"></i> Cargando...
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </section>
        </main>
        <footer class="footer-container">
            <p>&copy; <?php echo date('Y'); ?> Sistema Automatizado de Respuesta a Incidentes</p>
        </footer>
    </div>
    <style>
        .load-more-container {
            text-align: center;
            margin: 20px 0;
        }
        
        .load-more-btn {
            background-color: #2c3e50;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background-color 0.3s;
        }
        
        .load-more-btn:hover {
            background-color: #1a252f;
        }
        
        .load-more-btn:disabled {
            background-color: #95a5a6;
            cursor: not-allowed;
        }
        
        .loading-indicator {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 10px;
            color: #7f8c8d;
        }
        
        .loading-indicator i {
            margin-right: 8px;
        }
    </style>
    <script src="js/main.js"></script>
    <script>
        // Hacer las funciones disponibles globalmente
        window.viewAlertDetails = function(alertId) {
            // Redirigir a la página de detalles de la alerta
            window.location.href = 'alert-details.php?id=' + alertId;
        };

        window.blockIP = function(ip) {
            if (confirm('¿Estás seguro de que deseas bloquear la IP ' + ip + '?')) {
                fetch('api/block-ip.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'ip=' + encodeURIComponent(ip)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('La IP ' + ip + ' ha sido bloqueada correctamente');
                        // Recargar la página para ver los cambios
                        window.location.reload();
                    } else {
                        alert('Error al bloquear la IP: ' + (data.message || 'Error desconocido'));
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error al procesar la solicitud');
                });
            }
        };
        // Ya implementado en main.js
        // Mostrar/ocultar filtros
        const toggleBtn = document.getElementById('toggleFiltersBtn');
        const filtersPanel = document.getElementById('filtersPanel');
        let filtersOpen = false;
        
        if (toggleBtn && filtersPanel) {
            toggleBtn.addEventListener('click', () => {
                filtersOpen = !filtersOpen;
                filtersPanel.style.display = filtersOpen ? 'flex' : 'none';
                toggleBtn.innerHTML = filtersOpen ? '<i class="fas fa-times"></i> Cerrar filtros' : '<i class="fas fa-sliders-h"></i> Filtrar';
            });
        }
        
        // Función para cargar más alertas
        document.addEventListener('DOMContentLoaded', function() {
            const loadMoreBtn = document.getElementById('loadMoreBtn');
            if (loadMoreBtn) {
                loadMoreBtn.addEventListener('click', function() {
                    const offset = parseInt(this.getAttribute('data-offset'));
                    const loadingIndicator = document.getElementById('loadingIndicator');
                    const tableBody = document.getElementById('alertsTableBody');
                    
                    // Mostrar indicador de carga y deshabilitar el botón
                    loadMoreBtn.style.display = 'none';
                    loadingIndicator.style.display = 'block';
                    
                    // Construir la URL con los parámetros actuales
                    const urlParams = new URLSearchParams(window.location.search);
                    urlParams.set('offset', offset);
                    
                    // Realizar la petición AJAX
                    fetch(`alerts.php?${urlParams.toString()}`)
                        .then(response => response.text())
                        .then(html => {
                            // Crear un elemento temporal para parsear el HTML
                            const tempDiv = document.createElement('div');
                            tempDiv.innerHTML = html;
                            
                            // Extraer las filas de la tabla
                            const newTableBody = tempDiv.querySelector('#alertsTableBody');
                            if (!newTableBody) {
                                throw new Error('No se pudo encontrar el cuerpo de la tabla en la respuesta');
                            }
                            
                            // Agregar las nuevas filas a la tabla
                            const newRows = Array.from(newTableBody.querySelectorAll('tr'));
                            newRows.forEach(row => {
                                tableBody.appendChild(row.cloneNode(true));
                            });
                            
                            // Actualizar el botón de cargar más
                            const newLoadMoreBtn = tempDiv.querySelector('.load-more-btn');
                            if (newLoadMoreBtn) {
                                loadMoreBtn.setAttribute('data-offset', newLoadMoreBtn.getAttribute('data-offset'));
                                loadMoreBtn.style.display = 'inline-block';
                            } else {
                                loadMoreBtn.parentNode.remove();
                            }
                            
                            loadingIndicator.style.display = 'none';
                            
                            // Desplazarse suavemente a la primera nueva alerta
                            if (newRows.length > 0) {
                                newRows[0].scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                            }
                        })
                        .catch(error => {
                            console.error('Error al cargar más alertas:', error);
                            alert('Error al cargar más alertas. Por favor, inténtalo de nuevo.');
                            loadMoreBtn.style.display = 'inline-block';
                            loadingIndicator.style.display = 'none';
                        });
                });
            }
        });
    </script>
</body>
</html>
