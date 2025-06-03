<?php
// Este archivo sirve como endpoint para verificar nuevas alertas
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Manejar solicitudes OPTIONS para CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

try {
    // Conectar a la base de datos SQLite
    $db = new SQLite3('/var/www/html/database/alerts.db');
    
    // Habilitar el modo de excepciones
    if (!$db) {
        throw new Exception('No se pudo conectar a la base de datos');
    }

    // Obtener el timestamp de la última alerta que el cliente ya conoce
    $lastKnownTimestamp = isset($_GET['last_timestamp']) ? trim($_GET['last_timestamp']) : '1970-01-01 00:00:00';
    
    // Validar el formato del timestamp
    if ($lastKnownTimestamp !== '' && !preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $lastKnownTimestamp)) {
        throw new Exception('Formato de timestamp inválido. Use YYYY-MM-DD HH:MM:SS');
    }

    // Consultar nuevas alertas desde el último timestamp conocido
    $query = "SELECT * FROM alerts WHERE timestamp > :last_timestamp ORDER BY timestamp DESC LIMIT 50";
    $stmt = $db->prepare($query);
    $stmt->bindValue(':last_timestamp', $lastKnownTimestamp, SQLITE3_TEXT);
    $result = $stmt->execute();

    if (!$result) {
        throw new Exception('Error al ejecutar la consulta: ' . $db->lastErrorMsg());
    }

    // Preparar respuesta
    $newAlerts = [];
    $latestTimestamp = $lastKnownTimestamp;

    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $alert = [
            'id' => $row['id'],
            'timestamp' => $row['timestamp'],
            'source_ip' => $row['source_ip'],
            'destination_ip' => $row['destination_ip'] ?? '',
            'alert_message' => $row['alert_message'],
            'severity' => (int)$row['severity'],
            'protocol' => $row['protocol'] ?? 'unknown',
            'action_taken' => $row['action_taken'] ?? 'none',
            'raw_data' => $row['raw_data'] ?? ''
        ];
        
        $newAlerts[] = $alert;
        
        // Actualizar el timestamp más reciente
        if ($row['timestamp'] > $latestTimestamp) {
            $latestTimestamp = $row['timestamp'];
        }
    }

    // Obtener estadísticas actualizadas
    $total_alerts = (int)$db->querySingle("SELECT COUNT(*) FROM alerts");
    $high_severity = (int)$db->querySingle("SELECT COUNT(*) FROM alerts WHERE severity >= 2");
    $blocked_ips = (int)$db->querySingle("SELECT COUNT(*) FROM blocked_ips");
    $recent_alerts = (int)$db->querySingle("SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', 'localtime', '-24 hours')");

    // Cerrar la conexión a la base de datos
    $db->close();

    // Devolver respuesta JSON
    $response = [
        'success' => true,
        'has_new_alerts' => !empty($newAlerts),
        'alerts' => $newAlerts,
        'latest_timestamp' => $latestTimestamp,
        'stats' => [
            'total_alerts' => $total_alerts,
            'high_severity' => $high_severity,
            'blocked_ips' => $blocked_ips,
            'recent_alerts' => $recent_alerts
        ]
    ];
    
    echo json_encode($response);
    
} catch (Exception $e) {
    // En caso de error, devolver un mensaje de error
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);
}
?>
