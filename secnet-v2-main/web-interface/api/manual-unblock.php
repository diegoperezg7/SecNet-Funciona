<?php
header('Content-Type: text/html; charset=utf-8');
require_once '../includes/functions.php'; // Para validate_ip si la tienes ahí, o la definimos aquí

// Función para validar IP (si no está en functions.php)
if (!function_exists('validate_ip_php')) {
    function validate_ip_php($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
}

echo "<style>";
echo "body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }";
echo ".container { background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }";
echo ".message { padding: 10px; margin-bottom: 15px; border-radius: 4px; }";
echo ".success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }";
echo ".error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }";
echo "a { color: #007bff; text-decoration: none; }";
echo "a:hover { text-decoration: underline; }";
echo "</style>";

echo "<div class='container'>";
echo "<h1>Desbloqueo Manual de IP</h1>";

if (isset($_GET['ip'])) {
    $ip_to_unblock = $_GET['ip'];

    if (!validate_ip_php($ip_to_unblock)) {
        echo "<div class='message error'>IP proporcionada no válida: " . htmlspecialchars($ip_to_unblock) . "</div>";
    } else {
        echo "<p>Intentando desbloquear IP: <strong>" . htmlspecialchars($ip_to_unblock) . "</strong>...</p>";

        $api_url = 'http://python-responder:5000/api/unblock-ip';
        $payload = json_encode(['ip_address' => $ip_to_unblock]);

        $ch = curl_init($api_url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Content-Length: ' . strlen($payload)
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15); // Timeout de 15 segundos

        $result = curl_exec($ch);
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($result === false) {
            error_log('Error al conectar con la API Python para desbloquear: ' . $error);
            echo "<div class='message error'>Error al contactar la API del backend: " . htmlspecialchars($error) . "</div>";
        } else {
            $response_data = json_decode($result, true);
            if ($httpcode == 200 && isset($response_data['success']) && $response_data['success']) {
                echo "<div class='message success'>" . htmlspecialchars($response_data['message']) . "</div>";
            } else {
                $error_message = isset($response_data['message']) ? $response_data['message'] : 'Respuesta inesperada o error desde el backend.';
                if ($httpcode >= 400) {
                     error_log("Error desde API Python ($httpcode) para desbloquear $ip_to_unblock: $error_message");
                }
                echo "<div class='message error'>No se pudo desbloquear la IP. Backend respondió ($httpcode): " . htmlspecialchars($error_message) . "</div>";
            }
        }
    }
} else {
    echo "<p>Por favor, proporciona una IP para desbloquear usando el parámetro '?ip=' en la URL.</p>";
    echo "<p>Ejemplo: <a href='?ip=1.2.3.4'>?ip=1.2.3.4</a></p>";
}

echo "</div>";

?>
