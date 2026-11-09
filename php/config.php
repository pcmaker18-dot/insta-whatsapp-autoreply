<?php
// خادم PHP هنا مجرد "صندوق بريد": لا يحتوي على أي مفتاح سري.
// App Secret ورمز Instagram ورمز التحقق كلها محفوظة (مشفرة) في برنامج Windows فقط.
return [
    // بصمة SHA-256 لمفتاح API (وليس المفتاح نفسه).
    // اضغط «توليد مفتاح» في برنامج Windows، ثم الصق البصمة المنسوخة هنا.
    'api_key_sha256' => 'PASTE_SHA256_FROM_WINDOWS_APP',

    'db_path'   => __DIR__ . '/data/events.sqlite',
    'keep_days' => 7,           // حذف الرسائل المعالجة الأقدم من هذا
    'max_body'  => 1048576,     // أقصى حجم لطلب Webhook (1MB)
];
