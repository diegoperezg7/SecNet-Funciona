<?php
// Configuración de la zona horaria
date_default_timezone_set('Europe/Madrid');

// Otras configuraciones globales
define('DB_PATH', '/var/www/html/database/alerts.db');

// Función para obtener la fecha/hora actual en formato SQLite
function getCurrentDateTime() {
    return (new DateTime('now', new DateTimeZone('Europe/Madrid')))->format('Y-m-d H:i:s');
}

// Función para formatear fechas para mostrar al usuario
function formatDateTimeForDisplay($dateTime) {
    $date = new DateTime($dateTime, new DateTimeZone('Europe/Madrid'));
    return $date->format('d/m/Y H:i:s');
}
?>
