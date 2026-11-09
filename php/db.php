<?php
function db(array $cfg): PDO
{
    $dir = dirname($cfg['db_path']);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    $pdo = new PDO('sqlite:' . $cfg['db_path']);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA busy_timeout = 5000');
    // كل صف = طلب Webhook خام كما وصل من Meta + توقيعه (يتحقق منه برنامج Windows)
    $pdo->exec('CREATE TABLE IF NOT EXISTS events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        body       TEXT NOT NULL,
        signature  TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        delivered  INTEGER NOT NULL DEFAULT 0
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)');
    return $pdo;
}

function kv_get(PDO $db, string $k): ?string
{
    $s = $db->prepare('SELECT v FROM kv WHERE k = ?');
    $s->execute([$k]);
    $v = $s->fetchColumn();
    return $v === false ? null : (string) $v;
}

function kv_set(PDO $db, string $k, string $v): void
{
    $db->prepare('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v')
       ->execute([$k, $v]);
}
