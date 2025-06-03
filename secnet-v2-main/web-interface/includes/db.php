<?php
// Incluir configuración
require_once __DIR__ . '/config.php';

try {
    // Verificar si el archivo de la base de datos existe
    if (!file_exists(DB_PATH)) {
        throw new Exception("El archivo de la base de datos no existe en: " . DB_PATH);
    }
    
    // Verificar permisos del archivo
    if (!is_readable(DB_PATH) || !is_writable(DB_PATH)) {
        throw new Exception("No se tienen los permisos necesarios para acceder a la base de datos");
    }
    
    // Conectar a la base de datos SQLite
    $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT => 5, // Tiempo de espera de 5 segundos
        PDO::ATTR_PERSISTENT => false // No usar conexiones persistentes
    ]);
    
    // Activar el modo de compatibilidad con claves foráneas
    $pdo->exec('PRAGMA foreign_keys = ON');
    
} catch (PDOException $e) {
    error_log("Error de conexión a la base de datos SQLite: " . $e->getMessage());
    die("Error de conexión a la base de datos. Por favor, inténtelo de nuevo más tarde.");
} catch (Exception $e) {
    error_log("Error general de base de datos: " . $e->getMessage());
    die("Error de configuración de la base de datos. Contacte al administrador.");
}

// Función para validar IP
function isValidIP($ip) {
    if (empty($ip)) return false;
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

// Función para verificar si una IP es interna
function isInternalIP($ip) {
    // IPs internas RFC1918
    $internalRanges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16'
    ];
    
    foreach ($internalRanges as $range) {
        if (ip_in_range($ip, $range)) {
            return true;
        }
    }
    return false;
}

// Función auxiliar para verificar si una IP está en un rango
function ip_in_range($ip, $range) {
    if (strpos($range, '/') === false) {
        $range .= '/32';
    }
    
    list($range, $netmask) = explode('/', $range, 2);
    $ip_decimal = ip2long($ip);
    $range_decimal = ip2long($range);
    $wildcard_decimal = pow(2, (32 - $netmask)) - 1;
    $netmask_decimal = ~$wildcard_decimal;
    
    return (($ip_decimal & $netmask_decimal) === ($range_decimal & $netmask_decimal));
}
