<?php
// alert-details.php
// Muestra los detalles de una alerta específica y el historial de la IP

if (!isset($_GET['id'])) {
    header('Location: index.php');
    exit;
}

$id = intval($_GET['id']);
$db = new SQLite3('/var/www/html/database/alerts.db');

// Obtener detalles de la alerta
$stmt = $db->prepare('SELECT * FROM alerts WHERE id = :id');
$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
$result = $stmt->execute();
$alert = $result->fetchArray(SQLITE3_ASSOC);

if (!$alert) {
    echo '<h2>Alerta no encontrada</h2>';
    exit;
}

$source_ip = $alert['source_ip'];
// Obtener historial de la IP
$history = [];
if ($source_ip) {
    $hist_stmt = $db->prepare('SELECT * FROM alerts WHERE source_ip = :source_ip ORDER BY timestamp DESC LIMIT 20');
    $hist_stmt->bindValue(':source_ip', $source_ip, SQLITE3_TEXT);
    $hist_result = $hist_stmt->execute();
    while ($row = $hist_result->fetchArray(SQLITE3_ASSOC)) {
        $history[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Detalles de la Alerta</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-container">
                <a href="index.php" style="display:flex;align-items:center;text-decoration:none;">
                    <img src="assets/logo.png" alt="Logo">
                    <h1 class="secnet-title">SecNet</h1>
                </a>
            </div>
            <nav>
                <ul>
                    <li><a href="index.php"><i class="fas fa-tachometer-alt"></i> Panel</a></li>
                    <li><a href="alerts.php"><i class="fas fa-exclamation-triangle"></i> Alertas</a></li>
                </ul>
            </nav>
        </header>
        <main>
            <h2><i class="fas fa-eye"></i> Detalles de la Alerta</h2>
            <section class="alert-card">
                <div class="alert-card-header severity-<?= (int)$alert['severity'] ?>">
                    <i class="fas fa-bolt"></i> Alerta #<?= htmlspecialchars($alert['id']) ?>
                </div>
                <div class="alert-card-body">
                    <div class="alert-detail-row"><span class="alert-detail-label">Fecha/Hora:</span><span><?php
    $date = new DateTime($alert['timestamp'], new DateTimeZone('UTC'));
    $date->setTimezone(new DateTimeZone('Europe/Madrid'));
    echo $date->format('d-m-Y H:i');
?></span></div>
                    <div class="alert-detail-row"><span class="alert-detail-label">IP Origen:</span><span><?= htmlspecialchars($alert['source_ip']) ?></span></div>
                    <div class="alert-detail-row"><span class="alert-detail-label">IP Destino:</span><span><?= htmlspecialchars($alert['destination_ip']) ?></span></div>
                    <div class="alert-detail-row"><span class="alert-detail-label">Puerto:</span><span><?= !empty($alert['dest_port']) ? htmlspecialchars($alert['dest_port']) : 'N/A' ?></span></div>
                    <div class="alert-detail-row"><span class="alert-detail-label">Protocolo:</span><span><?= htmlspecialchars($alert['protocol']) ?></span></div>
                    <div class="alert-detail-row"><span class="alert-detail-label">Mensaje:</span><span><?= htmlspecialchars($alert['alert_message']) ?></span></div>
                    <div class="alert-detail-row"><span class="alert-detail-label">Severidad:</span><span class="severity-badge severity-<?= (int)$alert['severity'] ?>"><?= htmlspecialchars($alert['severity']) ?></span></div>
                </div>
            </section>
            <h3><i class="fas fa-history"></i> Historial de la IP</h3>
            <section class="alert-history-box">
                <table class="alert-history-table">
                    <thead>
                        <tr>
                            <th>Fecha/Hora</th>
                            <th>Mensaje</th>
                            <th>Severidad</th>
                            <th>Destino</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($history as $h): ?>
                        <tr>
                            <td><?php
    $date = new DateTime($h['timestamp'], new DateTimeZone('UTC'));
    $date->setTimezone(new DateTimeZone('Europe/Madrid'));
    echo $date->format('d-m-Y H:i');
?></td>
                            <td><?= htmlspecialchars($h['alert_message']) ?></td>
                            <td><span class="severity-badge severity-<?= (int)$h['severity'] ?>"><?= htmlspecialchars($h['severity']) ?></span></td>
                            <td><?= htmlspecialchars($h['destination_ip']) ?><?= !empty($h['dest_port']) ? ':' . htmlspecialchars($h['dest_port']) : '' ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </section>
            <a href="index.php" class="btn"><i class="fas fa-arrow-left"></i> Volver</a>
        </main>
    </div>
</body>
</html>
