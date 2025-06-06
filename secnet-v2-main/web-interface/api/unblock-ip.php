<?php
// Habilitar visualización de errores para depuración
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Manejar solicitudes OPTIONS para CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Verificar método
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'message' => 'Método no permitido'
    ]);
    exit;
}

// Obtener datos
$data = json_decode(file_get_contents('php://input'), true);
$ip_address = $data['ip'] ?? ''; // Cambiado de ip_address a ip para coincidir con el JavaScript

// Validar IP
if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => 'IP inválida'
    ]);
    exit;
}

try {
    // Ruta a la base de datos SQLite
    $db_path = __DIR__ . '/../../database/alerts.db';
    
    // Verificar si la base de datos existe
    if (!file_exists($db_path)) {
        throw new Exception('No se pudo encontrar la base de datos');
    }
    
    // Conectar a la base de datos
    $db = new PDO("sqlite:$db_path");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Verificar si la IP está bloqueada
    $stmt = $db->prepare("SELECT * FROM blocked_ips WHERE ip_address = ?");
    $stmt->execute([$ip_address]);
    if (!$stmt->fetch()) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'message' => 'La IP no está bloqueada actualmente'
        ]);
        exit;
    }
    
    // Eliminar reglas de iptables
    $commands = [
        "/sbin/iptables -D INPUT -s $ip_address -j DROP",
        "/sbin/iptables -D OUTPUT -d $ip_address -j DROP",
        "/sbin/ip6tables -D INPUT -s $ip_address -j DROP",
        "/sbin/ip6tables -D OUTPUT -d $ip_address -j DROP"
    ];
    
    $output = [];
    $all_success = true;
    
    // Ejecutar comandos iptables
    foreach ($commands as $cmd) {
        $output[] = "Ejecutando: $cmd";
        
        $return_var = 0;
        $cmd_output = [];
        
        // Usar sudo sin la contraseña (ya configurado en sudoers)
        exec("sudo $cmd 2>&1", $cmd_output, $return_var);
        $output = array_merge($output, $cmd_output);
        
        // No fallar si el comando falla (puede que la regla no exista)
        if ($return_var !== 0) {
            $output[] = "Advertencia: El comando falló con código $return_var";
        }
    }
    
    // Intentar guardar las reglas persistentemente
    $save_commands = [
        'if [ -f /usr/sbin/netfilter-persistent ]; then sudo /usr/sbin/netfilter-persistent save; fi',
        'if [ -f /sbin/iptables-save ]; then sudo /sbin/iptables-save | sudo tee /etc/iptables/rules.v4; fi',
        'if [ -f /sbin/ip6tables-save ]; then sudo /sbin/ip6tables-save | sudo tee /etc/iptables/rules.v6; fi'
    ];
    
    foreach ($save_commands as $save_cmd) {
        $output[] = "Ejecutando: $save_cmd";
        $save_output = [];
        $return_var = 0;
        
        exec($save_cmd . ' 2>&1', $save_output, $return_var);
        $output = array_merge($output, $save_output);
        
        if ($return_var !== 0) {
            $output[] = "Advertencia: No se pudo guardar las reglas persistentemente (código $return_var)";
        } else {
            $output[] = "Reglas guardadas exitosamente";
            break;
        }
    }
    
    // Iniciar transacción para la base de datos
    $db->beginTransaction();
    
    try {
        // Eliminar de la base de datos
        $stmt = $db->prepare("DELETE FROM blocked_ips WHERE ip_address = ?");
        $stmt->execute([$ip_address]);
        
        // Confirmar la transacción
        $db->commit();
        
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'message' => "IP $ip_address desbloqueada exitosamente",
            'details' => $output
        ]);
        
    } catch (Exception $db_error) {
        // Revertir la transacción en caso de error
        $db->rollBack();
        throw $db_error;
    }
    
} catch (Exception $e) {
    error_log("Error en unblock-ip.php: " . $e->getMessage());
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error al desbloquear IP',
        'details' => $e->getMessage(),
        'debug' => $output ?? []
    ]);
}
?> 