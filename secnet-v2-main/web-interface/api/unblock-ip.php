<?php
require_once '../config/database.php';
require_once '../includes/functions.php';

header('Content-Type: application/json');

// Verificar método
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        'success' => false,
        'message' => 'Método no permitido'
    ]);
    exit;
}

// Obtener datos
$data = json_decode(file_get_contents('php://input'), true);
$ip_address = $data['ip_address'] ?? '';

// Validar IP
if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
    echo json_encode([
        'success' => false,
        'message' => 'IP inválida'
    ]);
    exit;
}

try {
    $db = new PDO("sqlite:../../database/alerts.db");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Verificar si la IP está bloqueada
    $stmt = $db->prepare("SELECT * FROM blocked_ips WHERE ip_address = ?");
    $stmt->execute([$ip_address]);
    if (!$stmt->fetch()) {
        echo json_encode([
            'success' => false,
            'message' => 'IP no está bloqueada'
        ]);
        exit;
    }
    
    // Eliminar reglas de iptables
    $unblock_input_cmd = "sudo iptables -D INPUT -s $ip_address -j DROP";
    $unblock_output_cmd = "sudo iptables -D OUTPUT -d $ip_address -j DROP";
    $save_cmd = "sudo netfilter-persistent save";
    
    exec($unblock_input_cmd, $output, $return_var);
    if ($return_var !== 0) {
        throw new Exception("Error al eliminar regla INPUT");
    }
    
    exec($unblock_output_cmd, $output, $return_var);
    if ($return_var !== 0) {
        throw new Exception("Error al eliminar regla OUTPUT");
    }
    
    exec($save_cmd, $output, $return_var);
    if ($return_var !== 0) {
        throw new Exception("Error al guardar reglas de iptables");
    }
    
    // Eliminar de la base de datos
    $stmt = $db->prepare("DELETE FROM blocked_ips WHERE ip_address = ?");
    $stmt->execute([$ip_address]);
    
    echo json_encode([
        'success' => true,
        'message' => "IP $ip_address desbloqueada exitosamente"
    ]);
    
} catch (Exception $e) {
    error_log("Error en unblock-ip.php: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'Error al desbloquear IP',
        'details' => $e->getMessage()
    ]);
}
?> 