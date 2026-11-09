//! برنامج Windows بواجهة رسومية:
//! يسحب رسائل Instagram الجديدة من خادم PHP (api.php) ويرد عليها برسالة موحدة تحيل إلى واتساب.

#![windows_subsystem = "windows"]

use native_windows_derive as nwd;
use native_windows_gui as nwg;
use nwd::NwgUi;
use nwg::NativeUi;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ======================= الإعدادات =======================

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    server_url: String,
    api_key: String,
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
        .and_then(|p| p.parent().map(|d| d.join("settings.json")))
        .unwrap_or_else(|| PathBuf::from("settings.json"))
}

fn load_settings() -> Settings {
    std::fs::read_to_string(settings_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_settings(s: &Settings) -> Result<(), String> {
    let data = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    std::fs::write(settings_path(), data).map_err(|e| e.to_string())
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

// ======================= التعامل مع الخادم و Instagram =======================

#[derive(Deserialize)]
struct Event {
    id: i64,
    sender: String,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct FetchResp {
    #[serde(default)]
    events: Vec<Event>,
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

fn fetch_events(c: &reqwest::blocking::Client, s: &Settings) -> Result<Vec<Event>, String> {
    let r = c
        .get(api_url(s, "fetch"))
        .header("X-API-Key", s.api_key.trim())
        .send()
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("HTTP {}", r.status()));
    }
    r.json::<FetchResp>().map(|f| f.events).map_err(|e| e.to_string())
}

fn ack_events(c: &reqwest::blocking::Client, s: &Settings, ids: &[i64]) -> Result<(), String> {
    let r = c
        .post(api_url(s, "ack"))
        .header("X-API-Key", s.api_key.trim())
        .json(&json!({ "ids": ids }))
        .send()
        .map_err(|e| e.to_string())?;
    if r.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", r.status()))
    }
}

fn ping(s: &Settings) -> Result<i64, String> {
    let c = http_client()?;
    let r = c
        .get(api_url(s, "ping"))
        .header("X-API-Key", s.api_key.trim())
        .send()
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("HTTP {}", r.status()));
    }
    let v: serde_json::Value = r.json().map_err(|e| e.to_string())?;
    Ok(v["pending"].as_i64().unwrap_or(0))
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
        let body = r.text().unwrap_or_default();
        Err(format!("{code}: {body}"))
    }
}

/// الحلقة الخلفية: تسحب الرسائل كل بضع ثوانٍ وترد عليها
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
                    let recent = last_reply
                        .lock()
                        .unwrap()
                        .get(&ev.sender)
                        .map_or(false, |t| t.elapsed() < cooldown);
                    if recent {
                        done.push(ev.id);
                        continue;
                    }
                    let preview: String = ev.text.chars().take(40).collect();
                    match send_reply(&client, &s, &ev.sender, &text) {
                        Ok(()) => {
                            last_reply.lock().unwrap().insert(ev.sender.clone(), Instant::now());
                            log.log(format!("✔ تم الرد على {} — «{}»", ev.sender, preview));
                            done.push(ev.id);
                        }
                        Err(e) => {
                            let n = failures.entry(ev.id).or_insert(0);
                            *n += 1;
                            log.log(format!("✖ فشل الرد على {} (محاولة {}): {}", ev.sender, n, e));
                            if *n >= 3 {
                                done.push(ev.id); // نتوقف عن المحاولة بعد 3 مرات
                                failures.remove(&ev.id);
                            }
                        }
                    }
                }
                if !done.is_empty() {
                    if let Err(e) = ack_events(&client, &s, &done) {
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
    #[nwg_control(size: (700, 780), position: (200, 60), title: "الرد التلقائي على Instagram ← WhatsApp", flags: "MAIN_WINDOW|VISIBLE")]
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
    #[nwg_control(text: "مفتاح API (من config.php)")]
    #[nwg_layout_item(layout: grid, row: 1, col: 3)]
    lbl_key: nwg::Label,
    #[nwg_control(text: "", password: Some('*'))]
    #[nwg_layout_item(layout: grid, row: 1, col: 0, col_span: 3)]
    api_key: nwg::TextInput,

    // ---- رمز Instagram ----
    #[nwg_control(text: "رمز وصول Instagram")]
    #[nwg_layout_item(layout: grid, row: 2, col: 3)]
    lbl_token: nwg::Label,
    #[nwg_control(text: "", password: Some('*'))]
    #[nwg_layout_item(layout: grid, row: 2, col: 0, col_span: 3)]
    token: nwg::TextInput,

    // ---- رقم واتساب ----
    #[nwg_control(text: "رقم واتساب (213...)")]
    #[nwg_layout_item(layout: grid, row: 3, col: 3)]
    lbl_wa: nwg::Label,
    #[nwg_control(text: "")]
    #[nwg_layout_item(layout: grid, row: 3, col: 0, col_span: 3)]
    whatsapp: nwg::TextInput,

    // ---- المهلة والتحديث ----
    #[nwg_control(text: "عدم التكرار (ساعات)")]
    #[nwg_layout_item(layout: grid, row: 4, col: 3)]
    lbl_cool: nwg::Label,
    #[nwg_control(text: "24")]
    #[nwg_layout_item(layout: grid, row: 4, col: 2)]
    cooldown: nwg::TextInput,
    #[nwg_control(text: "الفحص كل (ثوانٍ)")]
    #[nwg_layout_item(layout: grid, row: 4, col: 1)]
    lbl_poll: nwg::Label,
    #[nwg_control(text: "5")]
    #[nwg_layout_item(layout: grid, row: 4, col: 0)]
    poll: nwg::TextInput,

    // ---- نص الرسالة ----
    #[nwg_control(text: "نص الرد ({whatsapp} يُستبدل برقمك):")]
    #[nwg_layout_item(layout: grid, row: 5, col: 0, col_span: 4)]
    lbl_msg: nwg::Label,
    #[nwg_control(text: "", flags: "VISIBLE|TAB_STOP|VSCROLL|AUTOVSCROLL")]
    #[nwg_layout_item(layout: grid, row: 6, col: 0, col_span: 4, row_span: 3)]
    message: nwg::TextBox,

    // ---- الأزرار ----
    #[nwg_control(text: "▶ تشغيل")]
    #[nwg_layout_item(layout: grid, row: 9, col: 3)]
    #[nwg_events(OnButtonClick: [App::on_start])]
    btn_start: nwg::Button,

    #[nwg_control(text: "■ إيقاف", enabled: false)]
    #[nwg_layout_item(layout: grid, row: 9, col: 2)]
    #[nwg_events(OnButtonClick: [App::on_stop])]
    btn_stop: nwg::Button,

    #[nwg_control(text: "💾 حفظ")]
    #[nwg_layout_item(layout: grid, row: 9, col: 1)]
    #[nwg_events(OnButtonClick: [App::on_save])]
    btn_save: nwg::Button,

    #[nwg_control(text: "اختبار الاتصال")]
    #[nwg_layout_item(layout: grid, row: 9, col: 0)]
    #[nwg_events(OnButtonClick: [App::on_test])]
    btn_test: nwg::Button,

    #[nwg_control(text: "الحالة: متوقف")]
    #[nwg_layout_item(layout: grid, row: 10, col: 0, col_span: 4)]
    status: nwg::Label,

    // ---- السجل ----
    #[nwg_control(text: "", readonly: true, flags: "VISIBLE|VSCROLL|AUTOVSCROLL")]
    #[nwg_layout_item(layout: grid, row: 11, col: 0, col_span: 4, row_span: 6)]
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
        self.token.set_text(&s.ig_token);
        self.whatsapp.set_text(&s.whatsapp);
        self.cooldown.set_text(&s.cooldown_hours.to_string());
        self.poll.set_text(&s.poll_seconds.to_string());
        self.message
            .set_text(&s.message.replace("\r\n", "\n").replace('\n', "\r\n"));
        self.append("جاهز. املأ الإعدادات ثم اضغط «تشغيل».");
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
            ig_token: self.token.text().trim().to_string(),
            whatsapp: self
                .whatsapp
                .text()
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect(),
            message: self.message.text().replace("\r\n", "\n"),
            cooldown_hours: self.cooldown.text().trim().parse().map_err(|_| "قيمة «عدم التكرار» يجب أن تكون رقماً")?,
            poll_seconds: self.poll.text().trim().parse().map_err(|_| "قيمة «الفحص كل» يجب أن تكون رقماً")?,
            graph_version: prev.graph_version,
        };
        if !s.server_url.starts_with("http") {
            return Err("رابط الخادم غير صحيح".into());
        }
        if s.api_key.is_empty() || s.ig_token.is_empty() {
            return Err("مفتاح API ورمز Instagram مطلوبان".into());
        }
        if s.whatsapp.len() < 8 {
            return Err("رقم واتساب غير صحيح (اكتبه بالصيغة الدولية مثل 213555123456)".into());
        }
        if s.message.trim().is_empty() {
            return Err("نص الرد فارغ".into());
        }
        Ok(s)
    }

    fn on_start(&self) {
        let s = match self.read_settings() {
            Ok(s) => s,
            Err(e) => {
                nwg::modal_error_message(&self.window, "خطأ", &e);
                return;
            }
        };
        let _ = save_settings(&s);
        let Some(log) = self.logger() else { return };

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let last = self.last_reply.clone();
        thread::spawn(move || worker(s, running, last, log));

        self.btn_start.set_enabled(false);
        self.btn_stop.set_enabled(true);
        self.status.set_text("الحالة: يعمل ✅");
    }

    fn on_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.btn_start.set_enabled(true);
        self.btn_stop.set_enabled(false);
        self.status.set_text("الحالة: متوقف");
    }

    fn on_save(&self) {
        match self.read_settings().and_then(|s| save_settings(&s)) {
            Ok(()) => nwg::modal_info_message(&self.window, "تم", "تم حفظ الإعدادات"),
            Err(e) => nwg::modal_error_message(&self.window, "خطأ", &e),
        };
    }

    fn on_test(&self) {
        let s = Settings {
            server_url: self.server.text().trim().to_string(),
            api_key: self.api_key.text().trim().to_string(),
            ..load_settings()
        };
        let Some(log) = self.logger() else { return };
        log.log("جارٍ اختبار الاتصال بالخادم...");
        thread::spawn(move || match ping(&s) {
            Ok(n) => log.log(format!("✔ الاتصال ناجح — رسائل في الانتظار: {n}")),
            Err(e) => log.log(format!("✖ فشل الاتصال: {e}")),
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
