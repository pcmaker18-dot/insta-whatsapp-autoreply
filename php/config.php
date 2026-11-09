<?php
// إعدادات خادم الاستقبال - عدّل القيم قبل الرفع
return [
    // نفس الكلمة التي تضعها في إعدادات Webhook على Meta
    'verify_token' => 'CHANGE_ME_verify_token',

    // App Secret من لوحة تطبيق Meta (للتحقق من أن الطلبات قادمة من Meta فعلاً)
    'app_secret'   => 'CHANGE_ME_app_secret',

    // مفتاح سري طويل وعشوائي، تضعه أيضاً في برنامج Windows
    'api_key'      => 'CHANGE_ME_long_random_api_key',

    // مكان قاعدة البيانات (المجلد data محمي بملف .htaccess)
    'db_path'      => __DIR__ . '/data/events.sqlite',

    // حذف الرسائل المعالجة الأقدم من عدد الأيام هذا
    'keep_days'    => 7,
];
