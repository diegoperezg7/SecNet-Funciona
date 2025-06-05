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
    <link rel="icon" type="image/png" href="assets/logo.png">
    <title>Detalles de Alerta - SecNet</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
    <style>
        /* Estilos para el modal */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.7);
            overflow: auto;
        }

        .modal-content {
            background-color: #2c3e50;
            margin: 5% auto;
            padding: 20px;
            border: 1px solid #34495e;
            width: 80%;
            max-width: 900px;
            border-radius: 5px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
            color: #ecf0f1;
            position: relative;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #34495e;
        }

        .close-modal {
            color: #aaa;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }

        .close-modal:hover {
            color: #e74c3c;
        }

        .modal-body {
            max-height: 60vh;
            overflow-y: auto;
            margin-bottom: 15px;
            background-color: #1a252f;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            padding-top: 15px;
            border-top: 1px solid #34495e;
        }

        .action-btn {
            padding: 8px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            transition: background-color 0.2s;
        }

        .action-btn.primary {
            background-color: #3498db;
            color: white;
        }

        .action-btn.primary:hover {
            background-color: #2980b9;
        }

        .action-btn:hover {
            opacity: 0.9;
        }

        /* Estilos para el JSON */
        #jsonContent {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-word;
            line-height: 1.5;
        }

        /* Estilos para los botones de acción */
        .alert-actions {
            margin-top: 20px;
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }
    </style>
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
            <section class="alert-card severity-<?= (int)$alert['severity'] ?>">
                <div class="alert-card-header">
                    <i class="fas fa-bolt"></i> Alerta #<?= htmlspecialchars($alert['id']) ?>
                </div>
                <div class="alert-card-body">
                    <div class="alert-detail-row"><span class="alert-detail-label">Fecha/Hora:</span><span><?php
    $date = new DateTime($alert['timestamp'], new DateTimeZone('UTC'));
    $date->setTimezone(new DateTimeZone('Europe/Madrid'));
    echo $date->format('d-m-Y H:i');
?></span></div>
                    <div class="alert-detail-row">
                        <span class="alert-detail-label">IP Origen:</span>
                        <span>
                            <?= htmlspecialchars($alert['source_ip']) ?>
                            <?php if (!empty($alert['source_port'])): ?>
                                <span class="port-badge">:<?= htmlspecialchars($alert['source_port']) ?></span>
                            <?php endif; ?>
                        </span>
                    </div>
                    <div class="alert-detail-row">
                        <span class="alert-detail-label">IP Destino:</span>
                        <span>
                            <?= htmlspecialchars($alert['destination_ip']) ?>
                            <?php if (!empty($alert['dest_port'])): ?>
                                <span class="port-badge">:<?= htmlspecialchars($alert['dest_port']) ?></span>
                            <?php endif; ?>
                        </span>
                    </div>
                    <div class="alert-detail-row"><span class="alert-detail-label">Protocolo:</span><span><?= htmlspecialchars($alert['protocol']) ?></span></div>
                    <div class="alert-detail-row"><span class="alert-detail-label">Mensaje:</span><span><?= htmlspecialchars($alert['alert_message']) ?></span></div>
                    <div class="alert-detail-row"><span class="alert-detail-label">Gravedad:</span><span class="gravedad-badge gravedad-<?= (int)$alert['severity'] ?>"><?= htmlspecialchars($alert['severity']) ?></span></div>
                    <div class="alert-actions">
                        <button id="showJsonBtn" class="action-btn primary">
                            <i class="fas fa-code"></i> Ver detalles completos
                        </button>
                    </div>
                </div>
            </section>
            <h3><i class="fas fa-history"></i> Historial de la IP</h3>
            <section class="alert-history-box">
                <table class="alert-history-table">
                    <thead>
                        <tr>
                            <th>Fecha/Hora</th>
                            <th>Mensaje</th>
                            <th>Gravedad</th>
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
                            <td><span class="gravedad-badge gravedad-<?= (int)$h['severity'] ?>"><?= htmlspecialchars($h['severity']) ?></span></td>
                            <td><?= htmlspecialchars($h['destination_ip']) ?><?= !empty($h['dest_port']) ? ':' . htmlspecialchars($h['dest_port']) : '' ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </section>
            <a href="index.php" class="btn"><i class="fas fa-arrow-left"></i> Volver</a>
        </main>
    </div>
    <!-- Modal para mostrar el JSON -->
    <div id="jsonModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Detalles completos de la alerta</h2>
                <span class="close-modal">&times;</span>
            </div>
            <div class="modal-body">
                <pre id="jsonContent"><?= htmlspecialchars(json_encode($alert, JSON_PRETTY_PRINT)) ?></pre>
            </div>
            <div class="modal-footer">
                <button id="copyJsonBtn" class="action-btn primary">
                    <i class="fas fa-copy"></i> Copiar al portapapeles
                </button>
                <button class="action-btn close-modal-btn">
                    <i class="fas fa-times"></i> Cerrar
                </button>
            </div>
        </div>
    </div>
    <script>
        // Manejo del modal
        document.addEventListener('DOMContentLoaded', function() {
            const modal = document.getElementById('jsonModal');
            const btn = document.getElementById('showJsonBtn');
            const closeBtns = document.querySelectorAll('.close-modal, .close-modal-btn');
            const copyBtn = document.getElementById('copyJsonBtn');

            // Abrir modal
            if (btn) {
                btn.onclick = function() {
                    modal.style.display = 'block';
                };
            }

            // Cerrar modal
            closeBtns.forEach(btn => {
                btn.onclick = function() {
                    modal.style.display = 'none';
                };
            });

            // Cerrar al hacer clic fuera del contenido
            window.onclick = function(event) {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            };

            // Copiar JSON al portapapeles
            if (copyBtn) {
                copyBtn.onclick = function() {
                    const jsonContent = document.getElementById('jsonContent').textContent;
                    navigator.clipboard.writeText(jsonContent).then(() => {
                        const originalText = copyBtn.innerHTML;
                        copyBtn.innerHTML = '<i class="fas fa-check"></i> ¡Copiado!';
                        setTimeout(() => {
                            copyBtn.innerHTML = originalText;
                        }, 2000);
                    }).catch(err => {
                        console.error('Error al copiar: ', err);
                        alert('Error al copiar al portapapeles');
                    });
                };
            }
        });
    </script>
</body>
</html>
