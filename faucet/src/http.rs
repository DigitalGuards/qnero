//! The five routes, and the order a claim is refused in.
//!
//! Nothing here touches the wallet. The worker thread owns it, and the only
//! way to reach it is the bounded channel below, which is also the rate limit
//! of last resort: one prover, one job at a time, and a full queue is a 503
//! with a `Retry-After` rather than a request held open for minutes.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use qnero_notes::Address;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::Config;
use crate::limits::{self, Refusal};
use crate::page;
use crate::store::{now_secs, ClaimStatus, Store};
use crate::worker::{Job, Shared};

/// How stale the node's last answer may be before `/health` reports 503. Three
/// block intervals at the 120 s target, so an ordinary wait for a block never
/// looks like an outage.
const NODE_STALE_SECS: u64 = 360;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<Mutex<Store>>,
    pub shared: Arc<Shared>,
    pub jobs: tokio::sync::mpsc::Sender<Job>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/drip", post(drip))
        .route("/drip/{id}", get(claim_status))
        .with_state(state)
}

/// The client this request came from.
///
/// nginx sets `X-Real-IP` from `$remote_addr`, and behind Cloudflare that is
/// the edge unless `real_ip_header CF-Connecting-IP` is configured, which the
/// runbook's nginx does. Either way the header is trusted only when the socket
/// peer is loopback, which is the one peer this server is meant to have: bound
/// to `127.0.0.1`, nginx is always the peer. Without that condition, a faucet
/// somebody bound to `0.0.0.0` would take every client's word for its own
/// address and the per-client limit would be no limit at all.
fn client_of(peer: SocketAddr, headers: &HeaderMap) -> String {
    let loopback = match peer.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if loopback {
        for name in ["x-real-ip", "cf-connecting-ip"] {
            if let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) {
                let first = value.split(',').next().unwrap_or("").trim();
                if !first.is_empty() {
                    return first.to_string();
                }
            }
        }
    }
    peer.ip().to_string()
}

async fn index(State(state): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        page::index(&state.config),
    )
        .into_response()
}

async fn app_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        page::APP_CSS,
    )
        .into_response()
}

async fn app_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        page::APP_JS,
    )
        .into_response()
}

/// What the on-box monitor and the external watchdog probe.
///
/// 200 only when the faucet could actually pay: the worker finished starting,
/// the node answered recently, and the spendable balance is above the floor. A
/// faucet that is up and drained is a faucet that refuses every claim, which
/// is an outage worth paging for even though the process is running.
///
/// The balance comes back twice, like every amount this service returns.
/// `balanceQuanta` is the count of pool steps the deployed monitor already
/// selects on by name and `balanceQnr` is the same figure in QNR, which is
/// what an alert reason should quote: a bare 48992 in a page reads as a
/// balance a hundred times what the faucet holds.
async fn health(State(state): State<AppState>) -> Response {
    let now = now_secs();
    let ready = state.shared.is_ready();
    let fresh = state.shared.node_fresh(NODE_STALE_SECS, now);
    let spendable = state.shared.spendable();
    let funded = spendable >= state.config.min_balance_quanta;
    let ok = ready && fresh && funded;
    let body = json!({
        "status": if ok { "ok" } else { "degraded" },
        "ready": ready,
        "nodeFresh": fresh,
        "funded": funded,
        "balanceQuanta": spendable,
        "balanceQnr": page::format_qnr(spendable),
        "chainHead": state.shared.chain_head.load(Ordering::Relaxed),
    });
    let code = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body)).into_response()
}

/// The deep check a watchdog asserts fields of. GET only, so a probe can
/// never submit a claim.
async fn status(State(state): State<AppState>) -> Response {
    let queued = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.queued_claims().ok())
        .map(|claims| claims.len())
        .unwrap_or(0);
    let paid = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.sent_total_quanta().ok())
        .unwrap_or(0);
    let spendable = state.shared.spendable();
    Json(json!({
        "configured": state.shared.is_ready(),
        "captchaEnabled": state.config.captcha_enabled(),
        "dripQuanta": state.config.drip_quanta,
        "dripQnr": page::format_qnr(state.config.drip_quanta),
        "cooldownHours": state.config.cooldown_hours(),
        "balanceQuanta": spendable,
        "balanceQnr": page::format_qnr(spendable),
        "notes": state.shared.notes.load(Ordering::Relaxed),
        "queued": queued,
        "queueCapacity": state.config.queue_depth,
        "paidQuanta": paid,
        "paidQnr": page::format_qnr(paid),
        "chainHead": state.shared.chain_head.load(Ordering::Relaxed),
        "address": state.shared.address.get(),
        "genesis": state.shared.genesis.get(),
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DripRequest {
    pub address: String,
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Queued {
    status: &'static str,
    id: i64,
    address: String,
    amount_quanta: u64,
    amount_qnr: String,
}

fn refuse(refusal: Refusal) -> Response {
    let mut response = (
        StatusCode::from_u16(refusal.status()).unwrap_or(StatusCode::BAD_REQUEST),
        Json(json!({
            "status": "refused",
            "reason": refusal.code(),
            "message": refusal.message(),
            "retryAfter": refusal.retry_after(),
        })),
    )
        .into_response();
    if let Some(seconds) = refusal.retry_after() {
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
}

async fn drip(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<DripRequest>,
) -> Response {
    let client = client_of(peer, &headers);
    let now = now_secs();

    // 1. The address. Nothing is read and nothing is written for a string
    //    that is not an address.
    //
    //    The ledger is keyed on `recipient.encode()` and never on what was
    //    posted. bech32m lowercases the human-readable part and maps `A-Z` to
    //    the same values as `a-z`, so `QN1...` and `qn1...` decode to one
    //    account; keying on the requester's spelling against a `TEXT` column
    //    with SQLite's binary collation would give that one account two
    //    cooldowns and two ledger rows.
    let recipient = match Address::decode(request.address.trim()) {
        Ok(address) => address,
        Err(error) => return refuse(Refusal::BadAddress(error.to_string())),
    };
    let wanted = recipient.encode();

    // 2 and 3. The two rate limits, one indexed read each, and both before
    //    Cloudflare is asked anything.
    //
    //    This pass is an optimization and not the gate: it is what stops an
    //    already-refused claim costing an outbound request to Cloudflare. The
    //    decision that counts is step 6, which reads and writes under one lock
    //    hold, because between here and there this task awaits.
    let (last_claim, in_window) = {
        let Ok(store) = state.store.lock() else {
            return internal("the claims ledger is poisoned");
        };
        let hash = store.ip_hash(&client);
        let last = store.last_claim_for_address(&wanted).unwrap_or(None);
        let count = store
            .claims_for_client(&hash, state.config.ip_window, now)
            .unwrap_or(0);
        (last, count)
    };
    if let Some(refusal) = limits::address_cooldown(last_claim, state.config.address_cooldown, now)
    {
        return refuse(refusal);
    }
    if let Some(refusal) =
        limits::client_limit(in_window, state.config.ip_limit, state.config.ip_window)
    {
        return refuse(refusal);
    }

    // 4. Can the faucet pay at all. Refusing here is what stops a claim
    //    consuming its requester's cooldown for a drip that was always going
    //    to fail inside note selection.
    if !state.shared.is_ready() || state.shared.spendable() < state.config.min_balance_quanta {
        return refuse(Refusal::Drained);
    }

    // 5. Turnstile, the one step that costs an outbound request.
    if let Some(secret) = state.config.turnstile_secret.clone() {
        let token = request.turnstile_token.clone().unwrap_or_default();
        if token.trim().is_empty() {
            return refuse(Refusal::CaptchaMissing);
        }
        let client_for_captcha = client.clone();
        let accepted = tokio::task::spawn_blocking(move || {
            crate::turnstile::verify(&secret, token.trim(), Some(&client_for_captcha))
        })
        .await
        .unwrap_or(false);
        if !accepted {
            return refuse(Refusal::CaptchaRefused);
        }
    }

    // 6. The decision, and the row. Both limits are read again and the row is
    //    written without the lock being released in between, which is what
    //    makes the pair atomic.
    //
    //    Step 2 is not enough on its own. Turnstile above is an await of tens
    //    to hundreds of milliseconds against Cloudflare, and every claim that
    //    is parked in it read a ledger none of them had written to yet: N
    //    simultaneous requests for one address would each see zero claims,
    //    each pass, and each enqueue. The row is written before anything is
    //    proved, so a claim that is accepted and then lost to a crash has
    //    still spent its cooldown, which is the safe side of that trade for a
    //    faucet.
    let amount = state.config.drip_quanta;
    let claim_id = {
        let Ok(store) = state.store.lock() else {
            return internal("the claims ledger is poisoned");
        };
        let hash = store.ip_hash(&client);
        let last = store.last_claim_for_address(&wanted).unwrap_or(None);
        if let Some(refusal) = limits::address_cooldown(last, state.config.address_cooldown, now) {
            return refuse(refusal);
        }
        let count = store
            .claims_for_client(&hash, state.config.ip_window, now)
            .unwrap_or(0);
        if let Some(refusal) =
            limits::client_limit(count, state.config.ip_limit, state.config.ip_window)
        {
            return refuse(refusal);
        }
        match store.record_queued(&wanted, &hash, amount, now) {
            Ok(id) => id,
            Err(error) => {
                eprintln!("faucet      could not record a claim: {error:#}");
                return internal("the claims ledger could not be written");
            }
        }
    };

    let job = Job {
        claim_id,
        address: recipient,
        quanta: amount,
    };
    if let Err(error) = state.jobs.try_send(job) {
        if let Ok(store) = state.store.lock() {
            let _ = store.mark_failed(claim_id, "queue-full", now);
        }
        eprintln!("faucet      the worker queue refused a job: {error}");
        return refuse(Refusal::Busy {
            retry_after: std::time::Duration::from_secs(60),
        });
    }

    (
        StatusCode::ACCEPTED,
        Json(Queued {
            status: "queued",
            id: claim_id,
            address: wanted,
            amount_quanta: amount,
            amount_qnr: page::format_qnr(amount),
        }),
    )
        .into_response()
}

async fn claim_status(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let claim = {
        let Ok(store) = state.store.lock() else {
            return internal("the claims ledger is poisoned");
        };
        store.claim(id).unwrap_or(None)
    };
    let Some(claim) = claim else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "status": "unknown", "message": "no such claim" })),
        )
            .into_response();
    };
    Json(json!({
        "status": claim.status.as_str(),
        "id": claim.id,
        "address": claim.address,
        "amountQuanta": claim.amount_quanta,
        "amountQnr": page::format_qnr(claim.amount_quanta),
        "includedAt": claim.included_at,
        // Only ever a reason code (`worker::failure_code`), never an error
        // carrying the node URL or the wallet store path.
        "reason": claim.detail,
        "requestedAt": claim.requested_at,
        "settledAt": claim.settled_at,
    }))
    .into_response()
}

fn internal(message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "status": "error", "message": message })),
    )
        .into_response()
}

/// What `ClaimStatus` answers with, kept beside the route that serves it.
impl ClaimStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                header::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                HeaderValue::from_str(value).expect("a header value"),
            );
        }
        map
    }

    #[test]
    fn a_proxy_header_is_trusted_from_loopback() {
        let peer: SocketAddr = "127.0.0.1:51000".parse().expect("a socket address");
        assert_eq!(
            client_of(peer, &headers(&[("x-real-ip", "203.0.113.9")])),
            "203.0.113.9"
        );
        assert_eq!(
            client_of(peer, &headers(&[("cf-connecting-ip", "203.0.113.9")])),
            "203.0.113.9"
        );
    }

    /// The header is a claim the client makes about itself. From anything but
    /// the proxy on loopback it is ignored, or a faucet bound to a public
    /// interface would have one rate-limit bucket per lie.
    #[test]
    fn a_proxy_header_from_anywhere_else_is_ignored() {
        let peer: SocketAddr = "198.51.100.4:51000".parse().expect("a socket address");
        assert_eq!(
            client_of(peer, &headers(&[("x-real-ip", "203.0.113.9")])),
            "198.51.100.4"
        );
    }

    /// `X-Forwarded-For` accumulates, and the client's own value is appended
    /// on the right. nginx sets `X-Real-IP` to a single address, but a chain
    /// arriving through either header has to reduce to its first entry.
    #[test]
    fn a_forwarded_chain_reduces_to_its_first_entry() {
        let peer: SocketAddr = "127.0.0.1:51000".parse().expect("a socket address");
        assert_eq!(
            client_of(
                peer,
                &headers(&[("x-real-ip", "203.0.113.9, 198.51.100.7")])
            ),
            "203.0.113.9"
        );
    }

    #[test]
    fn no_header_means_the_socket_peer() {
        let peer: SocketAddr = "127.0.0.1:51000".parse().expect("a socket address");
        assert_eq!(client_of(peer, &HeaderMap::new()), "127.0.0.1");
    }

    /// Every refusal that reaches a requester carries a status, a code and a
    /// message, and a rate limit also carries `Retry-After`, because a client
    /// told only "no" retries immediately.
    #[test]
    fn a_rate_limit_carries_retry_after() {
        let response = refuse(Refusal::AddressCooldown {
            retry_after: std::time::Duration::from_secs(3_600),
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .map(|v| v.to_str().unwrap()),
            Some("3600")
        );
    }

    #[test]
    fn a_malformed_address_is_a_400_with_no_retry_after() {
        let response = refuse(Refusal::BadAddress("not bech32".into()));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
    }
}
