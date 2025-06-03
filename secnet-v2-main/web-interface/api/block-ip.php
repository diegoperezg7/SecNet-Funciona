<?php
// Este archivo sirve como endpoint para bloquear IPs usando la API REST del backend Python
header('Content-Type: application/json');

// Verificar si se recibió una solicitud POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    error_log('Método no permitido: ' . $_SERVER['REQUEST_METHOD']);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

// Verificar si se proporcionó una IP
if (!isset($_POST['ip']) || empty($_POST['ip'])) {
    error_log('No se proporcionó dirección IP.');
    echo json_encode(['success' => false, 'message' => 'No IP address provided']);
    exit;
}

$ip = trim($_POST['ip']);

// Validar formato de IP
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    error_log('Formato de IP inválido: ' . $ip);
    echo json_encode(['success' => false, 'message' => 'Invalid IP address format']);
    exit;
}

$reason = isset($_POST['reason']) ? trim($_POST['reason']) : 'Manual block from dashboard';

// Conectar a la base de datos SQLite
$db = new SQLite3('/var/www/html/database/alerts.db');

// Verificar si la IP ya está bloqueada
$stmt = $db->prepare("SELECT COUNT(*) FROM blocked_ips WHERE ip_address = :ip");
$stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
$result = $stmt->execute();
$count = $result->fetchArray()[0];

if ($count > 0) {
    error_log("La IP $ip ya está bloqueada.");
    echo json_encode(['success' => false, 'message' => 'IP is already blocked']);
    $db->close();
    exit;
}

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
    echo json_encode(['success' => false, 'message' => 'Failed to contact backend API', 'details' => $error]);
    $db->close();
    exit;
}

$response = json_decode($result, true);
if ($httpcode !== 200 || !$response['success']) {
    error_log('Error al bloquear IP vía API Python: ' . ($response['message'] ?? 'Unknown error'));
    echo json_encode(['success' => false, 'message' => $response['message'] ?? 'Unknown error', 'details' => $response]);
    $db->close();
    exit;
}

// Insertar la IP en la tabla de IPs bloqueadas
$stmt = $db->prepare("INSERT INTO blocked_ips (ip_address, timestamp, reason) VALUES (:ip, datetime('now'), :reason)");
$stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
$stmt->bindValue(':reason', $reason, SQLITE3_TEXT);

if ($stmt->execute()) {
    echo json_encode(['success' => true, 'message' => $response['message']]);
} else {
    error_log('Error de base de datos: ' . $db->lastErrorMsg());
    echo json_encode(['success' => false, 'message' => 'Database error: ' . $db->lastErrorMsg()]);
}

$db->close();
// Dependencias: PHP con cURL y SQLite3, backend Python escuchando en http://localhost:5000
?>
