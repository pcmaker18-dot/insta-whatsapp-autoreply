//! برنامج Windows بواجهة رسومية للرد التلقائي على رسائل Instagram بإحالة إلى واتساب.
//!
//! - لا يفتح أي بورت: كل الاتصالات صادرة (نحو خادم PHP ونحو Instagram).
//! - كل المفاتيح هنا فقط: App Secret، رمز Instagram، رمز التحقق، مفتاح API.
//!   تُحفظ مشفرة بـ Windows DPAPI (لا يفكها إلا نفس مستخدم Windows على نفس الجهاز).
//! - خادم PHP يخزن طلبات Webhook خاماً، وهذا البرنامج يتحقق من توقيع Meta بنفسه.

#![windows_subsystem = "windows"]

use hmac::{Hmac, Mac};
use native_windows_derive as nwd;
use native_windows_gui as nwg;
use nwd::NwgUi;
use nwg::NativeUi;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

// ======================= تشفير DPAPI =======================

mod dpapi {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn run(data: &[u8], protect: bool) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };
        let ok = unsafe {
            if protect {
                CryptProtectData(&input, null(), null(), null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            } else {
                CryptUnprotectData(&input, null_mut(), null(), null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            }
        };
        if ok == 0 || out.pbData.is_null() {
            return Err("فشل تشفير/فك تشفير DPAPI".into());
        }
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        unsafe {
            LocalFree(out.pbData as _);
        }
        Ok(v)
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        run(data, true)
    }
    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        run(data, false)
    }
}

// ======================= الإعدادات =======================

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    server_url: String,
    api_key: String,
    verify_token: String,
    app_secret: String,
    ig_token: String,
    whatsapp: String,
    message: String,
    cooldown_hours: u64,
    poll_seconds: u64,
    graph_version: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server_url: "https://example.com/insta/api.php".into(),
            api_key: String::new(),
            verify_token: String::new(),
            app_secret: String::new(),
            ig_token: String::new(),
            whatsapp: "213555123456".into(),
            message: "مرحباً 👋 شكراً لتواصلك معنا.\nللرد السريع يرجى التواصل معنا عبر واتساب:\nhttps://wa.me/{whatsapp}".into(),
            cooldown_hours: 24,
            poll_seconds: 5,
            graph_version: "v21.0".into(),
        }
    }
}

fn settings_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("settings.dat")))
        .unwrap_or_else(|| PathBuf::from("settings.dat"))
}

fn load_settings() -> Settings {
    std::fs::read(settings_path())
        .ok()
        .and_then(|enc| dpapi::unprotect(&enc).ok())
        .and_then(|plain| serde_json::from_slice(&plain).ok())
        .unwrap_or_default()
}

fn save_settings(s: &Settings) -> Result<(), String> {
    let plain = serde_json::to_vec(s).map_err(|e| e.to_string())?;
    let enc = dpapi::protect(&plain)?;
    std::fs::write(settings_path(), enc).map_err(|e| e.to_string())
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).expect("random");
    hex::encode(buf)
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ======================= السجل (من الخيط الخلفي إلى الواجهة) =======================

#[derive(Clone)]
struct Logger {
    tx: Sender<String>,
    notice: nwg::NoticeSender,
}

impl Logger {
    fn log(&self, msg: impl Into<String>) {
        let line = format!("[{}] {}", chrono::Local::now().format("%H:%M:%S"), msg.into());
        let _ = self.tx.send(line);
        self.notice.notice();
    }
}

// ======================= الخادم =======================

#[derive(Deserialize)]
struct RawEvent {
    id: i64,
    body: String,
    signature: String,
}

#[derive(Deserialize)]
struct FetchResp {
    #[serde(default)]
    events: Vec<RawEvent>,
}

// حمولة Webhook من Meta
#[derive(Deserialize)]
struct WebhookPayload {
    #[serde(default)]
    object: String,
    #[serde(default)]
    entry: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    messaging: Vec<MessagingEvent>,
}

#[derive(Deserialize)]
struct MessagingEvent {
    sender: Party,
    #[serde(default)]
    message: Option<Message>,
}

#[derive(Deserialize)]
struct Party {
    id: String,
}

#[derive(Deserialize)]
struct Message {
    #[serde(default)]
    is_echo: bool,
    #[serde(default)]
    text: String,
}

fn api_url(s: &Settings, action: &str) -> String {
    let base = s.server_url.trim();
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}action={action}")
}

fn http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())
}

fn api_get(c: &reqwest::blocking::Client, s: &Settings, action: &str) -> Result<serde_json::Value, String> {
    let r = c
        .get(api_url(s, action))
        .header("X-API-Key", s.api_key.trim())
        .send()
        .map_err(|e| e.to_string())?;
    let code = r.status();
    if !code.is_success() {
        return Err(format!("HTTP {code}"));
    }
    r.json().map_err(|e| e.to_string())
}

fn api_post(
    c: &reqwest::blocking::Client,
    s: &Settings,
    action: &str,
    body: serde_json::Value,
) -> Result<(), String> {
    let r = c
        .post(api_url(s, action))
        .header("X-API-Key", s.api_key.trim())
        .json(&body)
        .send()
        .map_err(|e| e.to_string())?;
    let code = r.status();
    if code.is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {code}: {}", r.text().unwrap_or_default()))
    }
}

fn fetch_events(c: &reqwest::blocking::Client, s: &Settings) -> Result<Vec<RawEvent>, String> {
    let v = api_get(c, s, "fetch")?;
    serde_json::from_value::<FetchResp>(v)
        .map(|f| f.events)
        .map_err(|e| e.to_string())
}

fn signature_ok(app_secret: &str, body: &str, signature: &str) -> bool {
    let Some(hexsig) = signature.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hexsig) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(app_secret.as_bytes()) else {
        return false;
    };
    mac.update(body.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

fn send_reply(
    c: &reqwest::blocking::Client,
    s: &Settings,
    recipient: &str,
    text: &str,
) -> Result<(), String> {
    let url = format!("https://graph.instagram.com/{}/me/messages", s.graph_version);
    let r = c
        .post(url)
        .bearer_auth(s.ig_token.trim())
        .json(&json!({
            "recipient": { "id": recipient },
            "message": { "text": text }
        }))
        .send()
        .map_err(|e| e.to_string())?;
    if r.status().is_success() {
        Ok(())
    } else {
        let code = r.status();
        Err(format!("{code}: {}", r.text().unwrap_or_default()))
    }
}

/// ترسل رمز التحقق إلى الخادم حتى يجيب على مصافحة Meta
fn sync_verify_token(c: &reqwest::blocking::Client, s: &Settings) -> Result<(), String> {
    api_post(c, s, "set_verify", json!({ "verify_token": s.verify_token.trim() }))
}

// ======================= الحلقة الخلفية =======================

fn worker(
    s: Settings,
    running: Arc<AtomicBool>,
    last_reply: Arc<Mutex<HashMap<String, Instant>>>,
    log: Logger,
) {
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => {
            log.log(format!("تعذر إنشاء اتصال: {e}"));
            running.store(false, Ordering::SeqCst);
            return;
        }
    };

    match sync_verify_token(&client, &s) {
        Ok(()) => log.log("✔ تمت مزامنة رمز التحقق مع الخادم"),
        Err(e) => log.log(format!("⚠ تعذرت مزامنة رمز التحقق: {e}")),
    }

    let text = s
        .message
        .replace("{whatsapp}", s.whatsapp.trim())
        .replace("\r\n", "\n");
    let cooldown = Duration::from_secs(s.cooldown_hours * 3600);
    let mut failures: HashMap<i64, u32> = HashMap::new();

    log.log("▶ بدأ الرد التلقائي");

    while running.load(Ordering::SeqCst) {
        match fetch_events(&client, &s) {
            Ok(events) => {
                let mut done = Vec::new();

                for ev in events {
                    // 1) التحقق من أن الطلب قادم فعلاً من Meta
                    if !signature_ok(s.app_secret.trim(), &ev.body, &ev.signature) {
                        log.log(format!("⚠ تم تجاهل طلب #{} — توقيع غير صالح (تحقق من App Secret)", ev.id));
                        done.push(ev.id);
                        continue;
                    }

                    let payload: WebhookPayload = match serde_json::from_str(&ev.body) {
                        Ok(p) => p,
                        Err(_) => {
                            done.push(ev.id);
                            continue;
                        }
                    };
                    if payload.object != "instagram" {
                        done.push(ev.id);
                        continue;
                    }

                    // 2) الرد على كل رسالة واردة في هذا الطلب
                    let mut all_ok = true;
                    for entry in payload.entry {
                        for m in entry.messaging {
                            let Some(msg) = m.message else { continue };
                            if msg.is_echo {
                                continue;
                            }
                            let sender = m.sender.id;
                            let recent = last_reply
                                .lock()
                                .unwrap()
                                .get(&sender)
                                .map_or(false, |t| t.elapsed() < cooldown);
                            if recent {
                                continue;
                            }
                            let preview: String = msg.text.chars().take(40).collect();
                            match send_reply(&client, &s, &sender, &text) {
                                Ok(()) => {
                                    last_reply.lock().unwrap().insert(sender.clone(), Instant::now());
                                    log.log(format!("✔ تم الرد على {sender} — «{preview}»"));
                                }
                                Err(e) => {
                                    all_ok = false;
                                    log.log(format!("✖ فشل الرد على {sender}: {e}"));
                                }
                            }
                        }
                    }

                    if all_ok {
                        done.push(ev.id);
                    } else {
                        let n = failures.entry(ev.id).or_insert(0);
                        *n += 1;
                        if *n >= 3 {
                            log.log(format!("تم التخلي عن الطلب #{} بعد 3 محاولات", ev.id));
                            failures.remove(&ev.id);
                            done.push(ev.id);
                        }
                    }
                }

                if !done.is_empty() {
                    if let Err(e) = api_post(&client, &s, "ack", json!({ "ids": done })) {
                        log.log(format!("تعذر تأكيد المعالجة: {e}"));
                    }
                }
            }
            Err(e) => log.log(format!("خطأ في الاتصال بالخادم: {e}")),
        }

        let until = Instant::now() + Duration::from_secs(s.poll_seconds.max(2));
        while running.load(Ordering::SeqCst) && Instant::now() < until {
            thread::sleep(Duration::from_millis(200));
        }
    }
    log.log("■ تم الإيقاف");
}

// ======================= الواجهة الرسومية =======================

#[derive(Default, NwgUi)]
pub struct App {
    #[nwg_control(size: (720, 880), position: (200, 40), title: "الرد التلقائي على Instagram ← WhatsApp", flags: "MAIN_WINDOW|VISIBLE")]
    #[nwg_events(OnInit: [App::on_init], OnWindowClose: [App::on_close])]
    window: nwg::Window,

    #[nwg_layout(parent: window, spacing: 4)]
    grid: nwg::GridLayout,

    #[nwg_control]
    #[nwg_events(OnNotice: [App::on_notice])]
    notice: nwg::Notice,

    // ---- رابط الخادم ----
    #[nwg_control(text: "رابط api.php")]
    #[nwg_layout_item(layout: grid, row: 0, col: 3)]
    lbl_server: nwg::Label,
    #[nwg_control(text: "")]
    #[nwg_layout_item(layout: grid, row: 0, col: 0, col_span: 3)]
    server: nwg::TextInput,

    // ---- مفتاح API ----
    #[nwg_control(text: "مفتاح API")]
    #[nwg_layout_item(layout: grid, row: 1, col: 3)]
    lbl_key: nwg::Label,
    #[nwg_control(text: "", password: Some('*'))]
    #[nwg_layout_item(layout: grid, row: 1, col: 1, col_span: 2)]
    api_key: nwg::TextInput,
    #[nwg_control(text: "توليد مفتاح")]
    #[nwg_layout_item(layout: grid, row: 1, col: 0)]
    #[nwg_events(OnButtonClick: [App::on_gen_key])]
    btn_gen: nwg::Button,

    // ---- رمز التحقق ----
    #[nwg_control(text: "رمز التحقق (Verify Token)")]
    #[nwg_layout_item(layout: grid, row: 2, col: 3)]
    lbl_verify: nwg::Label,
    #[nwg_control(text: "", password: Some('*'))]
    #[nwg_layout_item(layout: grid, row: 2, col: 0, col_span: 3)]
    verify: nwg::TextInput,

    // ---- App Secret ----
    #[nwg_control(text: "App Secret (من Meta)")]
    #[nwg_layout_item(layout: grid, row: 3, col: 3)]
    lbl_secret: nwg::Label,
    #[nwg_control(text: "", password: Some('*'))]
    #[nwg_layout_item(layout: grid, row: 3, col: 0, col_span: 3)]
    app_secret: nwg::TextInput,

    // ---- رمز Instagram ----
    #[nwg_control(text: "رمز وصول Instagram")]
    #[nwg_layout_item(layout: grid, row: 4, col: 3)]
    lbl_token: nwg::Label,
    #[nwg_control(text: "", password: Some('*'))]
    #[nwg_layout_item(layout: grid, row: 4, col: 0, col_span: 3)]
    token: nwg::TextInput,

    // ---- رقم واتساب ----
    #[nwg_control(text: "رقم واتساب (213...)")]
    #[nwg_layout_item(layout: grid, row: 5, col: 3)]
    lbl_wa: nwg::Label,
    #[nwg_control(text: "")]
    #[nwg_layout_item(layout: grid, row: 5, col: 0, col_span: 3)]
    whatsapp: nwg::TextInput,

    // ---- المهلة والتحديث ----
    #[nwg_control(text: "عدم التكرار (ساعات)")]
    #[nwg_layout_item(layout: grid, row: 6, col: 3)]
    lbl_cool: nwg::Label,
    #[nwg_control(text: "24")]
    #[nwg_layout_item(layout: grid, row: 6, col: 2)]
    cooldown: nwg::TextInput,
    #[nwg_control(text: "الفحص كل (ثوانٍ)")]
    #[nwg_layout_item(layout: grid, row: 6, col: 1)]
    lbl_poll: nwg::Label,
    #[nwg_control(text: "5")]
    #[nwg_layout_item(layout: grid, row: 6, col: 0)]
    poll: nwg::TextInput,

    // ---- نص الرسالة ----
    #[nwg_control(text: "نص الرد ({whatsapp} يُستبدل برقمك):")]
    #[nwg_layout_item(layout: grid, row: 7, col: 0, col_span: 4)]
    lbl_msg: nwg::Label,
    #[nwg_control(text: "", flags: "VISIBLE|TAB_STOP|VSCROLL|AUTOVSCROLL")]
    #[nwg_layout_item(layout: grid, row: 8, col: 0, col_span: 4, row_span: 3)]
    message: nwg::TextBox,

    // ---- الأزرار ----
    #[nwg_control(text: "▶ تشغيل")]
    #[nwg_layout_item(layout: grid, row: 11, col: 3)]
    #[nwg_events(OnButtonClick: [App::on_start])]
    btn_start: nwg::Button,

    #[nwg_control(text: "■ إيقاف", enabled: false)]
    #[nwg_layout_item(layout: grid, row: 11, col: 2)]
    #[nwg_events(OnButtonClick: [App::on_stop])]
    btn_stop: nwg::Button,

    #[nwg_control(text: "💾 حفظ")]
    #[nwg_layout_item(layout: grid, row: 11, col: 1)]
    #[nwg_events(OnButtonClick: [App::on_save])]
    btn_save: nwg::Button,

    #[nwg_control(text: "اختبار الاتصال")]
    #[nwg_layout_item(layout: grid, row: 11, col: 0)]
    #[nwg_events(OnButtonClick: [App::on_test])]
    btn_test: nwg::Button,

    #[nwg_control(text: "الحالة: متوقف")]
    #[nwg_layout_item(layout: grid, row: 12, col: 0, col_span: 4)]
    status: nwg::Label,

    // ---- السجل ----
    #[nwg_control(text: "", readonly: true, flags: "VISIBLE|VSCROLL|AUTOVSCROLL")]
    #[nwg_layout_item(layout: grid, row: 13, col: 0, col_span: 4, row_span: 6)]
    log_box: nwg::TextBox,

    // ---- حالة داخلية ----
    running: Arc<AtomicBool>,
    last_reply: Arc<Mutex<HashMap<String, Instant>>>,
    tx: RefCell<Option<Sender<String>>>,
    rx: RefCell<Option<Receiver<String>>>,
}

impl App {
    fn on_init(&self) {
        let (tx, rx) = channel();
        *self.tx.borrow_mut() = Some(tx);
        *self.rx.borrow_mut() = Some(rx);

        let s = load_settings();
        self.server.set_text(&s.server_url);
        self.api_key.set_text(&s.api_key);
        self.verify.set_text(&s.verify_token);
        self.app_secret.set_text(&s.app_secret);
        self.token.set_text(&s.ig_token);
        self.whatsapp.set_text(&s.whatsapp);
        self.cooldown.set_text(&s.cooldown_hours.to_string());
        self.poll.set_text(&s.poll_seconds.to_string());
        self.message
            .set_text(&s.message.replace("\r\n", "\n").replace('\n', "\r\n"));

        if s.verify_token.is_empty() {
            // نولد رمز تحقق عشوائياً في أول تشغيل
            self.verify.set_text(&random_hex(16));
        }
        self.append("جاهز. المفاتيح تُحفظ مشفرة على هذا الجهاز فقط، ولا يُفتح أي بورت.");
    }

    fn logger(&self) -> Option<Logger> {
        self.tx.borrow().as_ref().map(|tx| Logger {
            tx: tx.clone(),
            notice: self.notice.sender(),
        })
    }

    fn append(&self, line: &str) {
        self.log_box.appendln(line);
    }

    fn read_settings(&self) -> Result<Settings, String> {
        let prev = load_settings();
        let s = Settings {
            server_url: self.server.text().trim().to_string(),
            api_key: self.api_key.text().trim().to_string(),
            verify_token: self.verify.text().trim().to_string(),
            app_secret: self.app_secret.text().trim().to_string(),
            ig_token: self.token.text().trim().to_string(),
            whatsapp: self.whatsapp.text().chars().filter(|c| c.is_ascii_digit()).collect(),
            message: self.message.text().replace("\r\n", "\n"),
            cooldown_hours: self
                .cooldown
                .text()
                .trim()
                .parse()
                .map_err(|_| "قيمة «عدم التكرار» يجب أن تكون رقماً")?,
            poll_seconds: self
                .poll
                .text()
                .trim()
                .parse()
                .map_err(|_| "قيمة «الفحص كل» يجب أن تكون رقماً")?,
            graph_version: prev.graph_version,
        };
        if !s.server_url.starts_with("https://") && !s.server_url.starts_with("http://") {
            return Err("رابط الخادم غير صحيح".into());
        }
        if s.api_key.len() < 16 {
            return Err("مفتاح API قصير — اضغط «توليد مفتاح»".into());
        }
        if s.verify_token.len() < 8 {
            return Err("رمز التحقق يجب أن يكون 8 أحرف على الأقل".into());
        }
        if s.app_secret.is_empty() || s.ig_token.is_empty() {
            return Err("App Secret ورمز Instagram مطلوبان".into());
        }
        if s.whatsapp.len() < 8 {
            return Err("رقم واتساب غير صحيح (اكتبه بالصيغة الدولية مثل 213555123456)".into());
        }
        if s.message.trim().is_empty() {
            return Err("نص الرد فارغ".into());
        }
        Ok(s)
    }

    fn on_gen_key(&self) {
        if !self.api_key.text().trim().is_empty() {
            let r = nwg::modal_message(
                &self.window,
                &nwg::MessageParams {
                    title: "تأكيد",
                    content: "يوجد مفتاح حالياً. توليد مفتاح جديد يتطلب تحديث config.php على الخادم. متابعة؟",
                    buttons: nwg::MessageButtons::YesNo,
                    icons: nwg::MessageIcons::Question,
                },
            );
            if !matches!(r, nwg::MessageChoice::Yes) {
                return;
            }
        }
        let key = random_hex(32);
        let hash = sha256_hex(&key);
        self.api_key.set_text(&key);
        let _ = nwg::Clipboard::set_data_text(&self.window, &hash);
        self.append("—— مفتاح API جديد ——");
        self.append("البصمة التالية نُسخت إلى الحافظة. الصقها في php/config.php في 'api_key_sha256':");
        self.append(&hash);
        self.append("ثم اضغط «حفظ».");
    }

    fn on_start(&self) {
        let s = match self.read_settings() {
            Ok(s) => s,
            Err(e) => {
                nwg::modal_error_message(&self.window, "خطأ", &e);
                return;
            }
        };
        if let Err(e) = save_settings(&s) {
            self.append(&format!("⚠ تعذر حفظ الإعدادات: {e}"));
        }
        let Some(log) = self.logger() else { return };

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let last = self.last_reply.clone();
        thread::spawn(move || worker(s, running, last, log));

        self.btn_start.set_enabled(false);
        self.btn_stop.set_enabled(true);
        self.btn_gen.set_enabled(false);
        self.status.set_text("الحالة: يعمل ✅");
    }

    fn on_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.btn_start.set_enabled(true);
        self.btn_stop.set_enabled(false);
        self.btn_gen.set_enabled(true);
        self.status.set_text("الحالة: متوقف");
    }

    fn on_save(&self) {
        match self.read_settings().and_then(|s| save_settings(&s)) {
            Ok(()) => nwg::modal_info_message(&self.window, "تم", "تم حفظ الإعدادات مشفرة"),
            Err(e) => nwg::modal_error_message(&self.window, "خطأ", &e),
        };
    }

    fn on_test(&self) {
        let s = Settings {
            server_url: self.server.text().trim().to_string(),
            api_key: self.api_key.text().trim().to_string(),
            verify_token: self.verify.text().trim().to_string(),
            ..load_settings()
        };
        let Some(log) = self.logger() else { return };
        log.log("جارٍ اختبار الاتصال بالخادم...");
        thread::spawn(move || {
            let c = match http_client() {
                Ok(c) => c,
                Err(e) => return log.log(format!("✖ {e}")),
            };
            match api_get(&c, &s, "ping") {
                Ok(v) => {
                    log.log(format!(
                        "✔ الاتصال ناجح — طلبات في الانتظار: {}",
                        v["pending"].as_i64().unwrap_or(0)
                    ));
                    if s.verify_token.len() >= 8 {
                        match sync_verify_token(&c, &s) {
                            Ok(()) => log.log("✔ تمت مزامنة رمز التحقق — يمكنك الآن تسجيل Webhook في Meta"),
                            Err(e) => log.log(format!("✖ تعذرت مزامنة رمز التحقق: {e}")),
                        }
                    }
                }
                Err(e) if e.contains("401") => {
                    log.log("✖ مفتاح API مرفوض — تأكد أن البصمة في config.php تطابق المفتاح")
                }
                Err(e) => log.log(format!("✖ فشل الاتصال: {e}")),
            }
        });
    }

    fn on_notice(&self) {
        if let Some(rx) = self.rx.borrow().as_ref() {
            while let Ok(line) = rx.try_recv() {
                self.append(&line);
            }
        }
    }

    fn on_close(&self) {
        self.running.store(false, Ordering::SeqCst);
        nwg::stop_thread_dispatch();
    }
}

fn main() {
    nwg::init().expect("تعذر تهيئة الواجهة");
    let _ = nwg::Font::set_global_family("Segoe UI");
    let _app = App::build_ui(Default::default()).expect("تعذر بناء الواجهة");
    nwg::dispatch_thread_events();
}
