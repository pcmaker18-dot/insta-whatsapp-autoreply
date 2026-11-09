<?php
// واجهة يتصل بها برنامج Windows (اتصال صادر منه فقط — لا بورتات مفتوحة على جهازك)
$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/db.php';

header('Content-Type: application/json; charset=utf-8');

// الخادم لا يعرف المفتاح نفسه، فقط بصمته SHA-256
$key = $_SERVER['HTTP_X_API_KEY'] ?? '';
if (!is_string($key) || $key === ''
    || !hash_equals(strtolower($cfg['api_key_sha256']), hash('sha256', $key))) {
    http_response_code(401);
    echo json_encode(['error' => 'unauthorized']);
    exit;
}

function body_json(): array
{
    $d = json_decode(file_get_contents('php://input'), true);
    return is_array($d) ? $d : [];
}

try {
    $db = db($cfg);
    $action = $_GET['action'] ?? 'fetch';
    $post = $_SERVER['REQUEST_METHOD'] === 'POST';

    switch ($action) {
        case 'ping':
            $pending = (int) $db->query('SELECT COUNT(*) FROM events WHERE delivered = 0')->fetchColumn();
            $vt = kv_get($db, 'verify_token');
            echo json_encode(['ok' => true, 'pending' => $pending, 'verify_token_set' => $vt !== null && $vt !== '']);
            break;

        case 'fetch':
            $rows = $db->query(
                'SELECT id, body, signature, created_at FROM events WHERE delivered = 0 ORDER BY id LIMIT 50'
            )->fetchAll();
            $out = [];
            foreach ($rows as $r) {
                $out[] = [
                    'id'         => (int) $r['id'],
                    'body'       => (string) $r['body'],
                    'signature'  => (string) $r['signature'],
                    'created_at' => (int) $r['created_at'],
                ];
            }
            echo json_encode(['events' => $out], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            break;

        case 'ack':
            if (!$post) { http_response_code(405); echo json_encode(['error' => 'POST required']); break; }
            $ids = array_values(array_filter(array_map('intval', body_json()['ids'] ?? []), function ($i) {
                return $i > 0;
            }));
            if ($ids) {
                $ph = implode(',', array_fill(0, count($ids), '?'));
                $db->prepare("UPDATE events SET delivered = 1 WHERE id IN ($ph)")->execute($ids);
            }
            $db->prepare('DELETE FROM events WHERE delivered = 1 AND created_at < ?')
               ->execute([time() - $cfg['keep_days'] * 86400]);
            echo json_encode(['ok' => true, 'acked' => count($ids)]);
            break;

        case 'set_verify':
            if (!$post) { http_response_code(405); echo json_encode(['error' => 'POST required']); break; }
            $vt = body_json()['verify_token'] ?? '';
            if (!is_string($vt) || strlen($vt) < 8 || strlen($vt) > 200) {
                http_response_code(400);
                echo json_encode(['error' => 'verify_token must be 8-200 chars']);
                break;
            }
            kv_set($db, 'verify_token', $vt);
            echo json_encode(['ok' => true]);
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
