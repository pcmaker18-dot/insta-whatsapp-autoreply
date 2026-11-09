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
    $pdo->exec('CREATE TABLE IF NOT EXISTS events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        mid        TEXT UNIQUE,
        sender     TEXT NOT NULL,
        text       TEXT,
        created_at INTEGER NOT NULL,
        delivered  INTEGER NOT NULL DEFAULT 0
    )');
    return $pdo;
}
