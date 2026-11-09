<?php
// يستقبل إشعارات Instagram من Meta ويحفظ الرسائل الجديدة في قائمة انتظار
$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/db.php';

// 1) التحقق عند تسجيل الـ Webhook (PHP يحوّل hub.mode إلى hub_mode)
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $mode  = $_GET['hub_mode'] ?? '';
    $token = $_GET['hub_verify_token'] ?? '';
    if ($mode === 'subscribe' && hash_equals($cfg['verify_token'], $token)) {
        header('Content-Type: text/plain');
        echo $_GET['hub_challenge'] ?? '';
    } else {
        http_response_code(403);
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

// 2) التحقق من توقيع Meta
$raw = file_get_contents('php://input');
$sig = $_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '';
$expected = 'sha256=' . hash_hmac('sha256', $raw, $cfg['app_secret']);
if (!hash_equals($expected, $sig)) {
    http_response_code(401);
    exit;
}

$data = json_decode($raw, true);
if (($data['object'] ?? '') !== 'instagram') {
    http_response_code(200);
    exit;
}

// 3) حفظ الرسائل الواردة (مع تجاهل رسائلنا نحن is_echo والتكرار)
try {
    $db = db($cfg);
    $stmt = $db->prepare(
        'INSERT OR IGNORE INTO events (mid, sender, text, created_at) VALUES (?, ?, ?, ?)'
    );
    foreach ($data['entry'] ?? [] as $entry) {
        foreach ($entry['messaging'] ?? [] as $ev) {
            $msg = $ev['message'] ?? null;
            if (!$msg || !empty($msg['is_echo'])) {
                continue;
            }
            $sender = $ev['sender']['id'] ?? '';
            if ($sender === '') {
                continue;
            }
            $stmt->execute([
                $msg['mid'] ?? uniqid('m_', true),
                $sender,
                $msg['text'] ?? '',
                time(),
            ]);
        }
    }
} catch (Throwable $e) {
    error_log('webhook error: ' . $e->getMessage());
    http_response_code(500); // Meta ستعيد المحاولة لاحقاً
    exit;
}

http_response_code(200);
echo 'EVENT_RECEIVED';
