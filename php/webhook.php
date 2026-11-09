<?php
// يستقبل Webhook من Meta ويخزنه خاماً مع توقيعه.
// التحقق من التوقيع ومعالجة الرسائل يتمان في برنامج Windows (الذي يملك App Secret).
$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/db.php';

try {
    $db = db($cfg);
} catch (Throwable $e) {
    error_log('webhook db error: ' . $e->getMessage());
    http_response_code(500);
    exit;
}

// 1) مصافحة التحقق عند تسجيل الـ Webhook.
//    رمز التحقق يرسله برنامج Windows إلى الخادم (ولا يُكتب في الملفات).
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $expected = kv_get($db, 'verify_token');
    $mode  = $_GET['hub_mode'] ?? '';
    $token = $_GET['hub_verify_token'] ?? '';
    if ($expected !== null && $expected !== '' && $mode === 'subscribe'
        && is_string($token) && hash_equals($expected, $token)) {
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

// 2) تخزين الطلب كما هو
$raw = file_get_contents('php://input', false, null, 0, $cfg['max_body'] + 1);
$sig = $_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '';

if ($raw === false || $raw === '' || strlen($raw) > $cfg['max_body']
    || !preg_match('/^sha256=[0-9a-f]{64}$/', $sig)) {
    http_response_code(400);
    exit;
}

try {
    $db->prepare('INSERT INTO events (body, signature, created_at) VALUES (?, ?, ?)')
       ->execute([$raw, $sig, time()]);
} catch (Throwable $e) {
    error_log('webhook insert error: ' . $e->getMessage());
    http_response_code(500); // Meta ستعيد المحاولة
    exit;
}

http_response_code(200);
echo 'EVENT_RECEIVED';
