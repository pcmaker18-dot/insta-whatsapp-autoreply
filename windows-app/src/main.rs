//! InstaAutoReply — برنامج Windows للرد التلقائي على رسائل Instagram بإحالة إلى واتساب.
//!
//! الواجهة: HTML/CSS داخل WebView2 (Tauri) — المجلد ui/
//!
//! الأمان:
//! - لا يفتح أي بورت: كل الاتصالات صادرة (نحو خادم PHP ونحو Instagram)، وبـ HTTPS فقط.
//! - كل المفاتيح هنا فقط، مشفرة بـ Windows DPAPI (settings.dat)، وكذلك ذاكرة المحادثات (memory.dat).
//! - يتحقق من توقيع Meta (HMAC-SHA256) لكل طلب، ويرفض الطلبات المكررة.
//!
//! الالتزام بسياسات Meta / Instagram:
//! - يرد فقط على رسائل وصلت خلال نافذة الـ 24 ساعة (Standard Messaging Window).
//! - رد واحد لكل شخص خلال مدة «عدم التكرار»، مع ذاكرة تبقى بعد إعادة التشغيل.
//! - يتوقف عن الرد الآلي في محادثة رد فيها موظف بنفسه (Human takeover).
//! - يحترم طلبات الإيقاف (STOP / توقف) ولا يراسل صاحبها آلياً بعد ذلك.
//! - تنويه بأن الرسالة آلية، وحد أقصى للردود في الساعة، وتوقف تلقائي عند حد المعدل.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, State};

type HmacSha256 = Hmac<Sha256>;

const WINDOW_SECS: i64 = 24 * 3600 - 10 * 60; // نافذة 24 ساعة مع هامش أمان 10 دقائق
const RATE_PAUSE: Duration = Duration::from_secs(15 * 60);
const STOP_WORDS: &[&str] = &[
    "stop", "unsubscribe", "توقف", "توقفوا", "إيقاف", "ايقاف", "الغاء", "إلغاء", "لا ترسل", "لا تراسلني", "arrête", "arrete",
];
const START_WORDS: &[&str] = &["start", "ابدأ", "ابدا", "استئناف"];

// ======================= تشفير DPAPI =======================

#[cfg(windows)]
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

#[cfg(not(windows))]
mod dpapi {
    pub fn protect(d: &[u8]) -> Result<Vec<u8>, String> {
        Ok(d.to_vec())
    }
    pub fn unprotect(d: &[u8]) -> Result<Vec<u8>, String> {
        Ok(d.to_vec())
    }
}

fn data_path(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .unwrap_or_else(|| PathBuf::from(name))
}

fn load_encrypted<T: for<'de> Deserialize<'de> + Default>(name: &str) -> T {
    std::fs::read(data_path(name))
        .ok()
        .and_then(|enc| dpapi::unprotect(&enc).ok())
        .and_then(|plain| serde_json::from_slice(&plain).ok())
        .unwrap_or_default()
}

fn save_encrypted<T: Serialize>(name: &str, v: &T) -> Result<(), String> {
    let plain = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    let enc = dpapi::protect(&plain)?;
    let path = data_path(name);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, enc).map_err(|e| format!("تعذر الحفظ: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("تعذر الحفظ: {e}"))
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
    // الامتثال والحماية
    max_per_hour: u64,
    min_interval_ms: u64,
    human_takeover_hours: u64,
    respect_stop: bool,
    bot_disclosure: bool,
    disclosure_text: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            api_key: String::new(),
            verify_token: String::new(),
            app_secret: String::new(),
            ig_token: String::new(),
            whatsapp: String::new(),
            message: "مرحباً 👋 شكراً لتواصلك معنا.\nللرد السريع يرجى التواصل معنا عبر واتساب:\nhttps://wa.me/{whatsapp}".into(),
            cooldown_hours: 24,
            poll_seconds: 5,
            graph_version: "v21.0".into(),
            max_per_hour: 150,
            min_interval_ms: 1500,
            human_takeover_hours: 12,
            respect_stop: true,
            bot_disclosure: true,
            disclosure_text: "🤖 رسالة آلية".into(),
        }
    }
}

fn normalize(mut s: Settings) -> Settings {
    s.server_url = s.server_url.trim().to_string();
    s.api_key = s.api_key.trim().to_string();
    s.verify_token = s.verify_token.trim().to_string();
    s.app_secret = s.app_secret.trim().to_string();
    s.ig_token = s.ig_token.trim().to_string();
    s.whatsapp = s.whatsapp.chars().filter(|c| c.is_ascii_digit()).collect();
    s.message = s.message.replace("\r\n", "\n").trim().to_string();
    s.disclosure_text = s.disclosure_text.trim().to_string();
    if s.graph_version.trim().is_empty() {
        s.graph_version = "v21.0".into();
    }
    s.poll_seconds = s.poll_seconds.clamp(2, 300);
    s.cooldown_hours = s.cooldown_hours.min(24 * 30);
    s.max_per_hour = s.max_per_hour.clamp(1, 1000);
    s.min_interval_ms = s.min_interval_ms.clamp(500, 60_000);
    s.human_takeover_hours = s.human_takeover_hours.min(24 * 7);
    s
}

fn is_local(url: &str) -> bool {
    let rest = url.trim_start_matches("http://");
    rest.starts_with("localhost") || rest.starts_with("127.0.0.1")
}

fn validate(s: &Settings) -> Result<(), String> {
    if !s.server_url.starts_with("https://") && !(s.server_url.starts_with("http://") && is_local(&s.server_url)) {
        return Err("رابط الخادم يجب أن يبدأ بـ https:// لحماية المفاتيح أثناء النقل".into());
    }
    if s.api_key.len() < 32 {
        return Err("مفتاح API قصير — اضغط «توليد»".into());
    }
    if s.verify_token.len() < 8 {
        return Err("رمز التحقق يجب أن يكون 8 أحرف على الأقل".into());
    }
    if s.app_secret.is_empty() {
        return Err("App Secret مطلوب للتحقق من أن الرسائل قادمة من Meta".into());
    }
    if s.ig_token.is_empty() {
        return Err("رمز وصول Instagram مطلوب".into());
    }
    if s.whatsapp.len() < 8 || s.whatsapp.starts_with('0') {
        return Err("رقم واتساب غير صحيح — اكتبه بالصيغة الدولية مثل 213555123456".into());
    }
    if s.message.is_empty() {
        return Err("نص الرد فارغ".into());
    }
    if s.message.chars().count() > 900 {
        return Err("نص الرد طويل جداً (الحد 900 حرف)".into());
    }
    Ok(())
}

fn reply_text(s: &Settings) -> String {
    let mut t = s.message.replace("{whatsapp}", &s.whatsapp);
    if s.bot_disclosure && !s.disclosure_text.is_empty() {
        t.push_str("\n\n");
        t.push_str(&s.disclosure_text);
    }
    t
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).expect("random");
    hex::encode(buf)
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ======================= ذاكرة المحادثات (مشفرة) =======================

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Memory {
    last_reply: HashMap<String, i64>,   // آخر رد آلي لكل مستخدم
    human_active: HashMap<String, i64>, // آخر رد بشري من الموظفين لكل مستخدم
    opted_out: HashSet<String>,         // من طلب عدم مراسلته آلياً
    seen_mids: VecDeque<String>,        // رسائل عولجت (منع التكرار وإعادة الإرسال)
    our_mids: VecDeque<String>,         // رسائل أرسلها البرنامج (لتمييزها عن ردود الموظفين)
}

impl Memory {
    fn seen(&self, mid: &str) -> bool {
        !mid.is_empty() && self.seen_mids.iter().any(|m| m == mid)
    }
    fn mark_seen(&mut self, mid: &str) {
        if mid.is_empty() || self.seen(mid) {
            return;
        }
        self.seen_mids.push_back(mid.to_string());
        while self.seen_mids.len() > 5000 {
            self.seen_mids.pop_front();
        }
    }
    fn mark_ours(&mut self, mid: &str) {
        if mid.is_empty() {
            return;
        }
        self.our_mids.push_back(mid.to_string());
        while self.our_mids.len() > 2000 {
            self.our_mids.pop_front();
        }
    }
    fn prune(&mut self) {
        let cutoff = unix_now() - 30 * 86400;
        self.last_reply.retain(|_, t| *t > cutoff);
        self.human_active.retain(|_, t| *t > cutoff);
    }
}

// ======================= الحالة المشتركة والأحداث =======================

#[derive(Default, Clone, Serialize)]
struct Stats {
    replied: u64,
    processed: u64,
    skipped: u64,
    errors: u64,
    last_activity: Option<String>,
}

struct Shared {
    running: Arc<AtomicBool>,
    memory: Arc<Mutex<Memory>>,
    stats: Arc<Mutex<Stats>>,
}

#[derive(Clone)]
struct Ctx {
    running: Arc<AtomicBool>,
    memory: Arc<Mutex<Memory>>,
    stats: Arc<Mutex<Stats>>,
    app: AppHandle,
}

#[derive(Clone, Serialize)]
struct LogLine {
    time: String,
    level: &'static str, // info | ok | warn | error
    text: String,
}

fn now_str() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

impl Ctx {
    fn log(&self, level: &'static str, text: impl Into<String>) {
        let _ = self.app.emit(
            "log",
            LogLine {
                time: now_str(),
                level,
                text: text.into(),
            },
        );
    }
    fn bump(&self, f: impl FnOnce(&mut Stats)) {
        let snapshot = {
            let mut s = self.stats.lock().unwrap();
            f(&mut s);
            s.last_activity = Some(now_str());
            s.clone()
        };
        let _ = self.app.emit("stats", snapshot);
    }
    fn alert(&self, text: &str) {
        let _ = self.app.emit("alert", text.to_string());
    }
    fn save_memory(&self) {
        let mem = self.memory.lock().unwrap();
        if let Err(e) = save_encrypted("memory.dat", &*mem) {
            self.log("warn", format!("تعذر حفظ ذاكرة المحادثات: {e}"));
        }
    }
}

/// إخفاء جزء من معرّف المستخدم في السجل (خصوصية)
fn mask(id: &str) -> String {
    let n = id.chars().count();
    if n <= 6 {
        return id.to_string();
    }
    let tail: String = id.chars().skip(n - 4).collect();
    format!("…{tail}")
}

// ======================= الخادم و Instagram =======================

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
    recipient: Option<Party>,
    #[serde(default)]
    timestamp: i64,
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
    mid: String,
    #[serde(default)]
    is_echo: bool,
    #[serde(default)]
    is_deleted: bool,
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
        .https_only(false) // يُفرض HTTPS عبر validate()، مع السماح بـ localhost للتجربة
        .user_agent("InstaAutoReply/0.4")
        .build()
        .map_err(|e| e.to_string())
}

fn api_get(c: &reqwest::blocking::Client, s: &Settings, action: &str) -> Result<Value, String> {
    let r = c
        .get(api_url(s, action))
        .header("X-API-Key", s.api_key.trim())
        .send()
        .map_err(|e| e.to_string())?;
    let code = r.status();
    if code.as_u16() == 401 {
        return Err("مفتاح API مرفوض — تأكد أن البصمة في config.php تطابق المفتاح".into());
    }
    if !code.is_success() {
        return Err(format!("HTTP {code}"));
    }
    r.json().map_err(|e| format!("رد غير مفهوم من الخادم: {e}"))
}

fn api_post(c: &reqwest::blocking::Client, s: &Settings, action: &str, body: Value) -> Result<(), String> {
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

enum SendError {
    Auth(String),      // رمز منتهي/ملغى — يجب الإيقاف
    RateLimit(String), // تجاوز حد المعدل — توقف مؤقت
    Permanent(String), // لا فائدة من الإعادة (خارج النافذة، مستخدم غير متاح...)
    Temporary(String), // خطأ شبكة/خادم — إعادة المحاولة لاحقاً
}

fn send_reply(c: &reqwest::blocking::Client, s: &Settings, recipient: &str, text: &str) -> Result<String, SendError> {
    let url = format!("https://graph.instagram.com/{}/me/messages", s.graph_version);
    let r = c
        .post(url)
        .bearer_auth(s.ig_token.trim())
        .json(&json!({
            "recipient": { "id": recipient },
            "message": { "text": text }
        }))
        .send()
        .map_err(|e| SendError::Temporary(e.to_string()))?;

    let status = r.status();
    let body: Value = r.json().unwrap_or(Value::Null);
    if status.is_success() {
        return Ok(body["message_id"].as_str().unwrap_or_default().to_string());
    }

    let err = &body["error"];
    let code = err["code"].as_i64().unwrap_or(0);
    let sub = err["error_subcode"].as_i64().unwrap_or(0);
    let msg = format!(
        "{} (code {code}{})",
        err["message"].as_str().unwrap_or(status.as_str()),
        if sub != 0 { format!("/{sub}") } else { String::new() }
    );
    Err(match code {
        190 | 102 => SendError::Auth(msg),
        4 | 17 | 32 | 613 | 80002 | 80006 => SendError::RateLimit(msg),
        _ if status.is_server_error() => SendError::Temporary(msg),
        _ => SendError::Permanent(msg),
    })
}

fn sync_verify_token(c: &reqwest::blocking::Client, s: &Settings) -> Result<(), String> {
    api_post(c, s, "set_verify", json!({ "verify_token": s.verify_token.trim() }))
}

fn normalize_text(t: &str) -> String {
    t.trim()
        .trim_matches(|c: char| c.is_ascii_punctuation() || c == '.' || c == '!' || c == '؟')
        .to_lowercase()
}

// ======================= القرار: نرد أم لا؟ =======================

enum Decision {
    Reply,
    Skip(String),
}

fn decide(s: &Settings, mem: &mut Memory, sender: &str, ts: i64, text: &str) -> Decision {
    let now = unix_now();
    let t = normalize_text(text);

    if s.respect_stop {
        if STOP_WORDS.iter().any(|w| t == *w) {
            mem.opted_out.insert(sender.to_string());
            return Decision::Skip("طلب عدم المراسلة — لن يُرسل له رد آلي بعد الآن".into());
        }
        if START_WORDS.iter().any(|w| t == *w) && mem.opted_out.remove(sender) {
            // عاد واشترك — نكمل ونرد
        } else if mem.opted_out.contains(sender) {
            return Decision::Skip("طلب سابقاً عدم المراسلة الآلية".into());
        }
    }

    if now - ts > WINDOW_SECS {
        return Decision::Skip("الرسالة أقدم من 24 ساعة — خارج نافذة المراسلة المسموحة".into());
    }

    if s.human_takeover_hours > 0 {
        if let Some(h) = mem.human_active.get(sender) {
            if now - *h < (s.human_takeover_hours * 3600) as i64 {
                return Decision::Skip("موظف يتابع هذه المحادثة بنفسه".into());
            }
        }
    }

    if let Some(last) = mem.last_reply.get(sender) {
        if now - *last < (s.cooldown_hours * 3600) as i64 {
            return Decision::Skip("تم الرد عليه مؤخراً".into());
        }
    }

    Decision::Reply
}

// ======================= الحلقة الخلفية =======================

fn worker(s: Settings, ctx: Ctx) {
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => {
            ctx.log("error", format!("تعذر إنشاء اتصال: {e}"));
            ctx.running.store(false, Ordering::SeqCst);
            let _ = ctx.app.emit("state", false);
            return;
        }
    };

    match sync_verify_token(&client, &s) {
        Ok(()) => ctx.log("ok", "تمت مزامنة رمز التحقق مع الخادم"),
        Err(e) => ctx.log("warn", format!("تعذرت مزامنة رمز التحقق: {e}")),
    }

    let text = reply_text(&s);
    let mut failures: HashMap<i64, u32> = HashMap::new();
    let mut sent_times: VecDeque<Instant> = VecDeque::new();
    let mut last_send: Option<Instant> = None;
    let mut paused_until: Option<Instant> = None;
    let mut server_down = false;
    let mut hour_cap_warned = false;

    ctx.memory.lock().unwrap().prune();
    ctx.log("ok", "بدأ الرد التلقائي");

    'outer: while ctx.running.load(Ordering::SeqCst) {
        // توقف مؤقت بعد حد معدل من Instagram
        if let Some(until) = paused_until {
            if Instant::now() < until {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
            paused_until = None;
            ctx.log("info", "استئناف بعد التوقف المؤقت");
        }

        let mut dirty = false;

        match fetch_events(&client, &s) {
            Ok(events) => {
                if server_down {
                    ctx.log("ok", "عاد الاتصال بالخادم");
                    server_down = false;
                }
                let mut done = Vec::new();

                for ev in events {
                    if !ctx.running.load(Ordering::SeqCst) {
                        break;
                    }
                    if !signature_ok(&s.app_secret, &ev.body, &ev.signature) {
                        ctx.log("warn", format!("رُفض طلب #{} — توقيع غير صالح (ليس من Meta أو App Secret خاطئ)", ev.id));
                        ctx.bump(|st| st.errors += 1);
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

                    let mut defer = false;

                    'msgs: for entry in payload.entry {
                        for m in entry.messaging {
                            if defer {
                                break 'msgs;
                            }
                            let Some(msg) = m.message else { continue };
                            if msg.is_deleted {
                                continue;
                            }
                            if ctx.memory.lock().unwrap().seen(&msg.mid) {
                                continue; // سبق معالجتها (حماية من التكرار)
                            }

                            let ts = if m.timestamp > 0 { m.timestamp / 1000 } else { unix_now() };

                            // رسالة صادرة من حسابك (echo): إما ردنا الآلي أو رد موظف
                            if msg.is_echo {
                                let mut mem = ctx.memory.lock().unwrap();
                                let ours = mem.our_mids.iter().any(|x| *x == msg.mid);
                                if !ours {
                                    if let Some(user) = m.recipient.as_ref().map(|r| r.id.clone()) {
                                        mem.human_active.insert(user.clone(), ts);
                                        drop(mem);
                                        if s.human_takeover_hours > 0 {
                                            ctx.log("info", format!("موظف رد على {} — إيقاف الرد الآلي لهذه المحادثة {} ساعة", mask(&user), s.human_takeover_hours));
                                        }
                                        mem = ctx.memory.lock().unwrap();
                                    }
                                }
                                mem.mark_seen(&msg.mid);
                                dirty = true;
                                continue;
                            }

                            let sender = m.sender.id;
                            let decision = {
                                let mut mem = ctx.memory.lock().unwrap();
                                decide(&s, &mut mem, &sender, ts, &msg.text)
                            };

                            match decision {
                                Decision::Skip(reason) => {
                                    ctx.log("info", format!("تخطي {} — {reason}", mask(&sender)));
                                    ctx.bump(|st| st.skipped += 1);
                                    ctx.memory.lock().unwrap().mark_seen(&msg.mid);
                                    dirty = true;
                                }
                                Decision::Reply => {
                                    // حد الردود في الساعة
                                    while sent_times.front().map_or(false, |t| t.elapsed() > Duration::from_secs(3600)) {
                                        sent_times.pop_front();
                                    }
                                    if sent_times.len() as u64 >= s.max_per_hour {
                                        if !hour_cap_warned {
                                            ctx.log("warn", format!("بلغ حد {} رد في الساعة — تأجيل البقية", s.max_per_hour));
                                            hour_cap_warned = true;
                                        }
                                        defer = true;
                                        continue;
                                    }
                                    hour_cap_warned = false;

                                    // مهلة بين الردود
                                    if let Some(l) = last_send {
                                        let gap = Duration::from_millis(s.min_interval_ms);
                                        if l.elapsed() < gap {
                                            thread::sleep(gap - l.elapsed());
                                        }
                                    }

                                    let preview: String = msg.text.chars().take(50).collect();
                                    let result = send_reply(&client, &s, &sender, &text);
                                    last_send = Some(Instant::now());

                                    match result {
                                        Ok(out_mid) => {
                                            sent_times.push_back(Instant::now());
                                            let mut mem = ctx.memory.lock().unwrap();
                                            mem.mark_ours(&out_mid);
                                            mem.last_reply.insert(sender.clone(), unix_now());
                                            mem.mark_seen(&msg.mid);
                                            drop(mem);
                                            dirty = true;
                                            ctx.bump(|st| st.replied += 1);
                                            ctx.log("ok", format!("تم الرد على {} — «{preview}»", mask(&sender)));
                                        }
                                        Err(SendError::Auth(e)) => {
                                            ctx.log("error", format!("رمز Instagram غير صالح أو منتهي — تم الإيقاف. {e}"));
                                            ctx.alert("رمز وصول Instagram منتهي أو ملغى. حدّثه من «الاتصال والمفاتيح».");
                                            ctx.bump(|st| st.errors += 1);
                                            ctx.running.store(false, Ordering::SeqCst);
                                            defer = true;
                                        }
                                        Err(SendError::RateLimit(e)) => {
                                            ctx.log("warn", format!("Instagram طلب التمهل — توقف مؤقت 15 دقيقة. {e}"));
                                            paused_until = Some(Instant::now() + RATE_PAUSE);
                                            defer = true;
                                        }
                                        Err(SendError::Permanent(e)) => {
                                            ctx.log("error", format!("تعذر الرد على {}: {e}", mask(&sender)));
                                            ctx.bump(|st| st.errors += 1);
                                            ctx.memory.lock().unwrap().mark_seen(&msg.mid);
                                            dirty = true;
                                        }
                                        Err(SendError::Temporary(e)) => {
                                            ctx.log("warn", format!("خطأ مؤقت أثناء الرد على {}: {e}", mask(&sender)));
                                            ctx.bump(|st| st.errors += 1);
                                            defer = true;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if defer {
                        let n = failures.entry(ev.id).or_insert(0);
                        *n += 1;
                        if *n >= 6 {
                            ctx.log("warn", format!("تم التخلي عن الطلب #{} بعد عدة محاولات", ev.id));
                            failures.remove(&ev.id);
                            done.push(ev.id);
                        }
                        // نتوقف عن هذه الدفعة ونعيد المحاولة في الدورة القادمة
                        if !done.is_empty() {
                            let _ = api_post(&client, &s, "ack", json!({ "ids": done }));
                        }
                        if dirty {
                            ctx.save_memory();
                        }
                        if !ctx.running.load(Ordering::SeqCst) {
                            break 'outer;
                        }
                        sleep_while_running(&ctx, s.poll_seconds);
                        continue 'outer;
                    }

                    failures.remove(&ev.id);
                    done.push(ev.id);
                    ctx.bump(|st| st.processed += 1);
                }

                if !done.is_empty() {
                    if let Err(e) = api_post(&client, &s, "ack", json!({ "ids": done })) {
                        ctx.log("error", format!("تعذر تأكيد المعالجة: {e}"));
                    }
                }
            }
            Err(e) => {
                if !server_down {
                    ctx.log("error", format!("خطأ في الاتصال بالخادم: {e}"));
                    server_down = true;
                }
            }
        }

        if dirty {
            ctx.save_memory();
        }
        sleep_while_running(&ctx, s.poll_seconds);
    }

    ctx.save_memory();
    ctx.log("info", "تم الإيقاف");
    let _ = ctx.app.emit("state", false);
}

fn sleep_while_running(ctx: &Ctx, secs: u64) {
    let until = Instant::now() + Duration::from_secs(secs.max(2));
    while ctx.running.load(Ordering::SeqCst) && Instant::now() < until {
        thread::sleep(Duration::from_millis(200));
    }
}

// ======================= أوامر الواجهة =======================

#[tauri::command]
fn get_settings() -> Settings {
    load_encrypted("settings.dat")
}

#[tauri::command]
fn save(settings: Settings) -> Result<(), String> {
    save_encrypted("settings.dat", &normalize(settings))
}

#[tauri::command]
fn generate_key() -> Value {
    let key = random_hex(32);
    let hash = sha256_hex(&key);
    json!({ "key": key, "hash": hash })
}

#[tauri::command]
fn key_hash(key: String) -> String {
    sha256_hex(key.trim())
}

#[tauri::command]
fn preview_text(settings: Settings) -> String {
    reply_text(&normalize(settings))
}

#[tauri::command]
async fn test_connection(settings: Settings) -> Result<Value, String> {
    let s = normalize(settings);
    tauri::async_runtime::spawn_blocking(move || -> Result<Value, String> {
        if !s.server_url.starts_with("https://") && !(s.server_url.starts_with("http://") && is_local(&s.server_url)) {
            return Err("رابط الخادم يجب أن يبدأ بـ https://".into());
        }
        let c = http_client()?;
        let mut v = api_get(&c, &s, "ping")?;
        if s.verify_token.len() >= 8 {
            sync_verify_token(&c, &s)?;
            v["verify_synced"] = json!(true);
        }
        // فحص رمز Instagram (بدون إرسال أي رسالة)
        if !s.ig_token.is_empty() {
            let url = format!("https://graph.instagram.com/{}/me?fields=username", s.graph_version);
            match c.get(url).bearer_auth(&s.ig_token).send() {
                Ok(r) if r.status().is_success() => {
                    let j: Value = r.json().unwrap_or(Value::Null);
                    v["ig_username"] = j["username"].clone();
                }
                Ok(r) => {
                    let j: Value = r.json().unwrap_or(Value::Null);
                    v["ig_error"] = json!(j["error"]["message"].as_str().unwrap_or("رمز Instagram مرفوض"));
                }
                Err(e) => v["ig_error"] = json!(e.to_string()),
            }
        }
        Ok(v)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn start(app: AppHandle, state: State<'_, Shared>, settings: Settings) -> Result<(), String> {
    let s = normalize(settings);
    validate(&s)?;
    save_encrypted("settings.dat", &s)?;
    if state.running.swap(true, Ordering::SeqCst) {
        return Err("البرنامج يعمل بالفعل".into());
    }
    let ctx = Ctx {
        running: state.running.clone(),
        memory: state.memory.clone(),
        stats: state.stats.clone(),
        app: app.clone(),
    };
    thread::spawn(move || worker(s, ctx));
    let _ = app.emit("state", true);
    Ok(())
}

#[tauri::command]
fn stop(state: State<'_, Shared>) {
    state.running.store(false, Ordering::SeqCst);
}

#[tauri::command]
fn get_status(state: State<'_, Shared>) -> Value {
    let stats = state.stats.lock().unwrap().clone();
    let mem = state.memory.lock().unwrap();
    json!({
        "running": state.running.load(Ordering::SeqCst),
        "stats": stats,
        "memory": {
            "contacts": mem.last_reply.len(),
            "opted_out": mem.opted_out.len(),
            "human": mem.human_active.len()
        }
    })
}

#[tauri::command]
fn reset_memory(state: State<'_, Shared>) -> Result<(), String> {
    let mut mem = state.memory.lock().unwrap();
    // نحتفظ بقائمة من طلبوا عدم المراسلة احتراماً لرغبتهم
    let opted = std::mem::take(&mut mem.opted_out);
    *mem = Memory::default();
    mem.opted_out = opted;
    save_encrypted("memory.dat", &*mem)
}

fn main() {
    let shared = Shared {
        running: Arc::new(AtomicBool::new(false)),
        memory: Arc::new(Mutex::new(load_encrypted::<Memory>("memory.dat"))),
        stats: Arc::new(Mutex::new(Stats::default())),
    };
    tauri::Builder::default()
        .manage(shared)
        .invoke_handler(tauri::generate_handler![
            get_settings,
            save,
            generate_key,
            key_hash,
            preview_text,
            test_connection,
            start,
            stop,
            get_status,
            reset_memory
        ])
        .run(tauri::generate_context!())
        .expect("تعذر تشغيل البرنامج");
}
