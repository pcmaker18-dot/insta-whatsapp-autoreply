//! رد تلقائي على رسائل Instagram المباشرة برسالة موحدة تحيل إلى واتساب.
//! يعتمد على Instagram Messaging API الرسمية (حساب احترافي Business/Creator).

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use std::{
    collections::HashMap,
    env,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    access_token: String,
    verify_token: String,
    app_secret: String,
    reply_text: String,
    graph_version: String,
    cooldown: Duration,
    http: reqwest::Client,
    // آخر وقت رددنا فيه على كل مرسل، حتى لا نكرر الرد في كل رسالة
    last_reply: Arc<Mutex<HashMap<String, Instant>>>,
}

// ---------- أنواع حمولة الـ Webhook ----------
#[derive(Deserialize)]
struct WebhookPayload {
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
}

#[derive(Deserialize)]
struct VerifyQuery {
    #[serde(rename = "hub.mode")]
    mode: Option<String>,
    #[serde(rename = "hub.verify_token")]
    token: Option<String>,
    #[serde(rename = "hub.challenge")]
    challenge: Option<String>,
}

// ---------- التحقق من الـ Webhook (GET) ----------
async fn verify(State(st): State<AppState>, Query(q): Query<VerifyQuery>) -> impl IntoResponse {
    if q.mode.as_deref() == Some("subscribe") && q.token.as_deref() == Some(&st.verify_token) {
        tracing::info!("تم التحقق من الـ webhook");
        (StatusCode::OK, q.challenge.unwrap_or_default())
    } else {
        (StatusCode::FORBIDDEN, String::new())
    }
}

// ---------- استقبال الأحداث (POST) ----------
async fn receive(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> StatusCode {
    if !signature_ok(&st.app_secret, &headers, &body) {
        tracing::warn!("توقيع غير صالح، تم رفض الطلب");
        return StatusCode::UNAUTHORIZED;
    }

    let payload: WebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("حمولة غير مفهومة: {e}");
            return StatusCode::OK;
        }
    };

    if payload.object != "instagram" {
        return StatusCode::OK;
    }

    for entry in payload.entry {
        for ev in entry.messaging {
            let Some(msg) = ev.message else { continue };
            if msg.is_echo {
                continue; // رسائلنا نحن، لا نرد عليها
            }
            let sender = ev.sender.id;
            if !should_reply(&st, &sender).await {
                continue;
            }
            let st2 = st.clone();
            // نرد في الخلفية حتى نعيد 200 لـ Meta بسرعة
            tokio::spawn(async move {
                if let Err(e) = send_reply(&st2, &sender).await {
                    tracing::error!("فشل الإرسال إلى {sender}: {e}");
                    st2.last_reply.lock().await.remove(&sender);
                } else {
                    tracing::info!("تم الرد على {sender}");
                }
            });
        }
    }
    StatusCode::OK
}

fn signature_ok(secret: &str, headers: &HeaderMap, body: &[u8]) -> bool {
    let Some(sig) = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("sha256="))
    else {
        return false;
    };
    let Ok(expected) = hex::decode(sig) else { return false };
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

async fn should_reply(st: &AppState, sender: &str) -> bool {
    let mut map = st.last_reply.lock().await;
    let now = Instant::now();
    match map.get(sender) {
        Some(t) if now.duration_since(*t) < st.cooldown => false,
        _ => {
            map.insert(sender.to_string(), now);
            true
        }
    }
}

async fn send_reply(st: &AppState, recipient: &str) -> Result<(), String> {
    let url = format!("https://graph.instagram.com/{}/me/messages", st.graph_version);
    let res = st
        .http
        .post(&url)
        .bearer_auth(&st.access_token)
        .json(&json!({
            "recipient": { "id": recipient },
            "message": { "text": st.reply_text }
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if res.status().is_success() {
        Ok(())
    } else {
        let code = res.status();
        let txt = res.text().await.unwrap_or_default();
        Err(format!("{code}: {txt}"))
    }
}

fn need(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("المتغير {key} غير موجود في .env"))
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let whatsapp = need("WHATSAPP_NUMBER"); // مثال: 213555123456 (بدون + أو أصفار بادئة)
    let default_text = format!(
        "مرحباً 👋 شكراً لتواصلك معنا.\nللرد السريع يرجى التواصل معنا عبر واتساب:\nhttps://wa.me/{whatsapp}"
    );

    let state = AppState {
        access_token: need("IG_ACCESS_TOKEN"),
        verify_token: need("VERIFY_TOKEN"),
        app_secret: need("APP_SECRET"),
        reply_text: env::var("REPLY_TEXT").unwrap_or(default_text),
        graph_version: env::var("GRAPH_VERSION").unwrap_or_else(|_| "v21.0".into()),
        cooldown: Duration::from_secs(
            env::var("COOLDOWN_HOURS")
                .ok()
                .and_then(|h| h.parse::<u64>().ok())
                .unwrap_or(24)
                * 3600,
        ),
        http: reqwest::Client::new(),
        last_reply: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/webhook", get(verify).post(receive))
        .with_state(state);

    let port = env::var("PORT").unwrap_or_else(|_| "8080".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("تعذر فتح المنفذ");
    tracing::info!("الخادم يعمل على المنفذ {port}");
    axum::serve(listener, app).await.unwrap();
}
