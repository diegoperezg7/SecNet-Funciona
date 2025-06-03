<?php
// Initialize response
$response = [
    'success' => false,
    'message' => 'Unknown action'
];

// Connect to SQLite database
$db = new SQLite3('/var/www/html/database/alerts.db');

// Process actions
if (isset($_GET['action'])) {
    $action = $_GET['action'];
    
    // Block IP action
    if ($action === 'block' && isset($_GET['ip']) && isset($_GET['alert_id'])) {
        $ip = trim($_GET['ip']);
        $alert_id = intval($_GET['alert_id']);

        // Validar formato de IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            error_log('Formato de IP inválido: ' . $ip);
            $response = [
                'success' => false,
                'message' => "Invalid IP address format"
            ];
        } else {
            // Check if IP is already blocked
            $is_blocked = $db->querySingle("SELECT COUNT(*) FROM blocked_ips WHERE ip_address = '" . SQLite3::escapeString($ip) . "'") > 0;
            
            if ($is_blocked) {
                error_log("La IP $ip ya está bloqueada.");
                $response = [
                    'success' => false,
                    'message' => "IP $ip is already blocked"
                ];
            } else {
                // Get alert details for reason
                $alert_stmt = $db->prepare("SELECT alert_message FROM alerts WHERE id = :id");
                $alert_stmt->bindValue(':id', $alert_id, SQLITE3_INTEGER);
                $alert_result = $alert_stmt->execute();
                $alert_row = $alert_result->fetchArray(SQLITE3_ASSOC);
                $reason = $alert_row ? $alert_row['alert_message'] : 'Manual block from web interface';

                // Llamar a la API REST Python
                $api_url = 'http://localhost:5000/api/block-ip';
                $payload = json_encode(['ip_address' => $ip, 'reason' => $reason]);
                $ch = curl_init($api_url);
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
                curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_HTTPHEADER, [
                    'Content-Type: application/json',
                    'Content-Length: ' . strlen($payload)
                ]);
                $result = curl_exec($ch);
                $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $error = curl_error($ch);
                curl_close($ch);

                if ($result === false) {
                    error_log('Error al conectar con la API Python: ' . $error);
                    $response = [
                        'success' => false,
                        'message' => 'Failed to contact backend API',
                        'details' => $error
                    ];
                } else {
                    $api_response = json_decode($result, true);
                    if ($httpcode !== 200 || !$api_response['success']) {
                        error_log('Error al bloquear IP vía API Python: ' . ($api_response['message'] ?? 'Unknown error'));
                        $response = [
                            'success' => false,
                            'message' => $api_response['message'] ?? 'Unknown error',
                            'details' => $api_response
                        ];
                    } else {
                        // Add to blocked_ips table
                        $timestamp = date('Y-m-d H:i:s');
                        $block_stmt = $db->prepare("INSERT INTO blocked_ips (ip_address, timestamp, reason) VALUES (:ip, :timestamp, :reason)");
                        $block_stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
                        $block_stmt->bindValue(':timestamp', $timestamp, SQLITE3_TEXT);
                        $block_stmt->bindValue(':reason', $reason, SQLITE3_TEXT);
                        $result = $block_stmt->execute();
                        if ($result) {
                            // Update alert action
                            $update_stmt = $db->prepare("UPDATE alerts SET action_taken = 'Manually blocked IP' WHERE id = :id");
                            $update_stmt->bindValue(':id', $alert_id, SQLITE3_INTEGER);
                            $update_stmt->execute();
                            $response = [
                                'success' => true,
                                'message' => "Successfully blocked IP: $ip"
                            ];
                        } else {
                            error_log('Error de base de datos: ' . $db->lastErrorMsg());
                            $response = [
                                'success' => false,
                                'message' => "Failed to add IP to blocked list: " . $db->lastErrorMsg()
                            ];
                        }
                    }
                }
            }
        }
    }
    
    // Show alert details
    elseif ($action === 'details' && isset($_GET['id'])) {
        $id = intval($_GET['id']);
        
        $stmt = $db->prepare("SELECT * FROM alerts WHERE id = :id");
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $alert = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($alert) {
            // Format the JSON data
            $raw_data = json_decode($alert['raw_data'], true);
            
            // Display the details page
            ?>
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Alert Details - Security Incident Response System</title>
                <link rel="stylesheet" href="css/style.css">
            </head>
            <body>
                <div class="container">
                    <header>
                        <h1>SecNet</h1>
                        <nav>
                            <ul>
                                <li><a href="index.php">Dashboard</a></li>
                                <li><a href="alerts.php">Alertas</a></li>
                            </ul>
                        </nav>
                    </header>
                    
                    <main>
                        <section class="alert-details">
                            <h2>Detalles</h2>
                            <div class="back-link">
                                <a href="alerts.php">&larr; Volver a Alertas</a>
                            </div>
                            
                            <div class="detail-card">
                                <h3>Alert #<?php echo $alert['id']; ?>: <?php echo htmlspecialchars($alert['alert_message']); ?></h3>
                                
                                <div class="detail-grid">
                                    <div class="detail-item">
                                        <span class="label">Fecha:</span>
                                        <span class="value"><?php echo date('Y-m-d H:i:s', strtotime($alert['timestamp'])); ?></span>
                                    </div>
                                    
                                    <div class="detail-item">
                                        <span class="label">IP de Origen:</span>
                                        <span class="value"><?php echo htmlspecialchars($alert['source_ip']); ?></span>
                                    </div>
                                    
                                    <div class="detail-item">
                                        <span class="label">Destination IP:</span>
                                        <span class="value"><?php echo htmlspecialchars($alert['destination_ip']); ?></span>
                                    </div>
                                    
                                    <div class="detail-item">
                                        <span class="label">Protocol:</span>
                                        <span class="value"><?php echo htmlspecialchars($alert['protocol']); ?></span>
                                    </div>
                                    
                                    <div class="detail-item">
                                        <span class="label">Severity:</span>
                                        <span class="value severity <?php echo ($alert['severity'] >= 2) ? 'high' : 'low'; ?>">
                                            <?php echo $alert['severity']; ?>
                                        </span>
                                    </div>
                                    
                                    <div class="detail-item">
                                        <span class="label">Action Taken:</span>
                                        <span class="value"><?php echo htmlspecialchars($alert['action_taken']); ?></span>
                                    </div>
                                </div>
                                
                                <div class="raw-data">
                                    <h4>Raw Alert Data</h4>
                                    <pre><?php echo json_encode($raw_data, JSON_PRETTY_PRINT); ?></pre>
                                </div>
                                
                                <?php
                                // Check if IP is already blocked
                                $ip = $alert['source_ip'];
                                $is_blocked = $db->querySingle("SELECT COUNT(*) FROM blocked_ips WHERE ip_address = '" . SQLite3::escapeString($ip) . "'") > 0;
                                
                                if (!$is_blocked) {
                                    echo "<div class='action-buttons'>";
                                    echo "<a href='actions.php?action=block&ip={$alert['source_ip']}&alert_id={$alert['id']}' class='block-button'>Block IP</a>";
                                    echo "</div>";
                                } else {
                                    echo "<div class='action-buttons'>";
                                    echo "<span class='blocked-status'>IP Already Blocked</span>";
                                    echo "</div>";
                                }
                                ?>
                            </div>
                        </section>
                    </main>
                    
                    <footer>
                        <p>&copy; <?php echo date('Y'); ?> Automated Incident Response System</p>
                    </footer>
                </div>
            </body>
            </html>
            <?php
            exit;
        } else {
            $response = [
                'success' => false,
                'message' => "Alert not found"
            ];
        }
    }
}

// Close database connection
$db->close();

// Dependencias: PHP con cURL y SQLite3, backend Python escuchando en http://localhost:5000
if (isset($response) && !headers_sent()) {
    header('Content-Type: application/json');
    echo json_encode($response);
}
?>
