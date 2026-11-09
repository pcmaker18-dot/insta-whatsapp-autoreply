# Instagram → WhatsApp Auto-Reply

رد تلقائي على رسائل Instagram المباشرة برسالة موحدة تطلب من المرسل التواصل عبر واتساب.

```
Instagram ──webhook──▶ php/webhook.php ──▶ SQLite
                                              │
     Instagram API ◀── windows-app (GUI) ◀── php/api.php
```

## المجلدات

| المجلد | الوصف |
|---|---|
| `php/` | يُرفع على استضافتك: يستقبل Webhook من Meta ويخزن الرسائل |
| `windows-app/` | برنامج Windows بواجهة رسومية يسحب الرسائل ويرد عليها |
| `server-rust/` | بديل: خادم Rust مستقل يرد مباشرة بدون PHP ولا Windows |

## 1) خادم PHP

1. عدّل `php/config.php`: `verify_token` و`app_secret` و`api_key` (مفتاح طويل عشوائي).
2. ارفع مجلد `php` على استضافة تدعم PHP 7.4+ مع امتداد `pdo_sqlite` وشهادة HTTPS.
3. تأكد أن المجلد `data` قابل للكتابة وأنه محمي (ملف `.htaccess` موجود، وعلى Nginx امنع الوصول إليه يدوياً).
4. في لوحة تطبيق Meta → Instagram → Webhooks:
   - Callback URL: `https://your-domain/php/webhook.php`
   - Verify token: نفس `verify_token`
   - اشترك في `messages`

## 2) برنامج Windows

- حمّل الملف `insta-autoreply-gui.exe` من تبويب **Actions** (آخر عملية بناء ← Artifacts)،
  أو ابنِه بنفسك: `cd windows-app && cargo build --release`.
- شغّله واملأ: رابط `api.php`، مفتاح API، رمز وصول Instagram، رقم واتساب، ونص الرد.
- اضغط «اختبار الاتصال» ثم «تشغيل». يجب أن يبقى البرنامج مفتوحاً ليرد.

الإعدادات تُحفظ في `settings.json` بجانب البرنامج (يحتوي الرمز، فلا تشاركه).

## ملاحظات

- يتطلب حساب Instagram احترافياً (Business/Creator).
- في وضع التطوير يرد التطبيق فقط على الحسابات المضافة كمختبِرين؛ للعموم يلزم App Review.
- لا يُعاد الرد على نفس الشخص قبل مرور مدة «عدم التكرار» (24 ساعة افتراضياً).
