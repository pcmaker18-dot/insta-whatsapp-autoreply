<?php
// واجهة يستعملها برنامج Windows لسحب الرسائل وتأكيد معالجتها
$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/db.php';

header('Content-Type: application/json; charset=utf-8');

$key = $_SERVER['HTTP_X_API_KEY'] ?? ($_GET['key'] ?? '');
if (!is_string($key) || !hash_equals($cfg['api_key'], $key)) {
    http_response_code(401);
    echo json_encode(['error' => 'unauthorized']);
    exit;
}

try {
    $db = db($cfg);
    $action = $_GET['action'] ?? 'fetch';

    switch ($action) {
        case 'ping':
            $pending = (int) $db->query('SELECT COUNT(*) FROM events WHERE delivered = 0')->fetchColumn();
            echo json_encode(['ok' => true, 'pending' => $pending]);
            break;

        case 'fetch':
            $rows = $db->query(
                'SELECT id, sender, text, created_at FROM events WHERE delivered = 0 ORDER BY id LIMIT 50'
            )->fetchAll();
            $rows = array_map(function ($r) {
                return [
                    'id'         => (int) $r['id'],
                    'sender'     => (string) $r['sender'],
                    'text'       => (string) ($r['text'] ?? ''),
                    'created_at' => (int) $r['created_at'],
                ];
            }, $rows);
            echo json_encode(['events' => $rows], JSON_UNESCAPED_UNICODE);
            break;

        case 'ack':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'POST required']);
                break;
            }
            $body = json_decode(file_get_contents('php://input'), true);
            $ids = array_values(array_filter(
                array_map('intval', $body['ids'] ?? []),
                function ($i) { return $i > 0; }
            ));
            if ($ids) {
                $ph = implode(',', array_fill(0, count($ids), '?'));
                $db->prepare("UPDATE events SET delivered = 1 WHERE id IN ($ph)")->execute($ids);
            }
            // تنظيف الرسائل القديمة
            $db->prepare('DELETE FROM events WHERE delivered = 1 AND created_at < ?')
               ->execute([time() - $cfg['keep_days'] * 86400]);
            echo json_encode(['ok' => true, 'acked' => count($ids)]);
            break;

        default:
            http_response_code(400);
            echo json_encode(['error' => 'unknown action']);
    }
} catch (Throwable $e) {
    error_log('api error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'server error']);
}
