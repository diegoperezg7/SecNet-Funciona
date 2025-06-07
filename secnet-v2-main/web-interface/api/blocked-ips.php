<?php
require_once '../config/database.php';
require_once '../includes/functions.php';

header('Content-Type: application/json');

try {
    $db = new PDO("sqlite:/var/www/html/database/alerts.db");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Obtener lista de IPs bloqueadas
    $stmt = $db->query("SELECT ip_address, timestamp, reason FROM blocked_ips ORDER BY timestamp DESC");
    $blocked_ips = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'success' => true,
        'blocked_ips' => $blocked_ips
    ]);
    
} catch (PDOException $e) {
    error_log("Error en blocked-ips.php: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'Error al obtener la lista de IPs bloqueadas',
        'details' => $e->getMessage()
    ]);
}
?> 