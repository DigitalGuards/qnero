//! The HTTP surface, driven end to end against a worker that never proves.
//!
//! A real drip is about ten seconds of proving and then up to one 120 second
//! block, so nothing here proves anything: the worker end of the queue is a
//! plain receiver this test holds, and what is exercised is everything in
//! front of it. That is where the rules live. Which claims are refused, in
//! what order, with which status and which reason code, and what a restart
//! does to a claim that was accepted and never settled, are all decidable
//! without a chain, and the rehearsal in `docs/OPS-DEV.md` is what covers the
//! part that is not.
//!
//! The server is a real listener on an ephemeral port rather than a router
//! driven in memory, because one of the rules under test is about the socket
//! peer: the proxy headers are trusted only from loopback, and a test that
//! synthesised `ConnectInfo` would be asserting its own fixture.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qnero_faucet::config::Config;
use qnero_faucet::http::{router, AppState};
use qnero_faucet::store::{now_secs, Store};
use qnero_faucet::worker::{Job, Shared};

/// A running faucet, minus the wallet.
struct Harness {
    base: String,
    store: Arc<Mutex<Store>>,
    shared: Arc<Shared>,
    /// The worker end of the queue. Held so the channel stays open; read to
    /// assert what the HTTP side actually enqueued.
    jobs: tokio::sync::mpsc::Receiver<Job>,
    _dir: tempdir::TempDir,
}

/// The smallest temporary directory that works without a dependency: a unique
/// path under the test's own target directory, removed on drop.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the clock is after 1970")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("qnero-faucet-{tag}-{unique}"));
            std::fs::create_dir_all(&path).expect("a temporary directory");
            Self(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn config_in(dir: &std::path::Path) -> Config {
    Config {
        node_url: "http://127.0.0.1:1".into(),
        seed_path: dir.join("spend.seed"),
        transparent_seed_path: dir.join("transparent.seed"),
        expect_address: None,
        db_path: dir.join("claims.sqlite"),
        drip_quanta: 1_000,
        address_cooldown: Duration::from_secs(86_400),
        ip_limit: 3,
        ip_window: Duration::from_secs(86_400),
        min_balance_quanta: 5_000,
        fund_chunk_quanta: 50_000,
        fund_notes: 4,
        turnstile_secret: None,
        turnstile_site_key: None,
        bind: "127.0.0.1:0".parse().expect("a socket address"),
        queue_depth: 4,
        ip_hash_key_path: dir.join("ip-hash.key"),
    }
}

async fn start(config: Config) -> Harness {
    let dir = tempdir::TempDir::new("http");
    let mut config = config;
    // Rewrite the paths into this harness's own directory, so two tests
    // running at once never share a ledger.
    config.db_path = dir.path().join("claims.sqlite");
    config.ip_hash_key_path = dir.path().join("ip-hash.key");

    let store = Arc::new(Mutex::new(
        Store::open(&config.db_path, &config.ip_hash_key_path).expect("a ledger"),
    ));
    let shared = Arc::new(Shared::default());
    // The worker's steady state: started, funded, and the node answering.
    shared.ready.store(true, Ordering::Relaxed);
    shared.spendable_quanta.store(100_000, Ordering::Relaxed);
    shared.notes.store(4, Ordering::Relaxed);
    shared.chain_head.store(42, Ordering::Relaxed);
    shared.last_seen_node.store(now_secs(), Ordering::Relaxed);
    let _ = shared.address.set("qn1faucet".into());

    let queue_depth = config.queue_depth;
    let (tx, jobs) = tokio::sync::mpsc::channel(queue_depth);
    let state = AppState {
        config: Arc::new(config),
        store: Arc::clone(&store),
        shared: Arc::clone(&shared),
        jobs: tx,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral port");
    let address = listener.local_addr().expect("the bound address");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    Harness {
        base: format!("http://{address}"),
        store,
        shared,
        jobs,
        _dir: dir,
    }
}

/// One request, on a blocking thread because the client is `ureq`.
async fn request(
    method: &'static str,
    url: String,
    body: Option<String>,
    client: Option<&'static str>,
) -> (u16, serde_json::Value, Option<String>) {
    tokio::task::spawn_blocking(move || {
        let mut call = match method {
            "POST" => ureq::post(&url),
            _ => ureq::get(&url),
        };
        if let Some(address) = client {
            call = call.set("X-Real-IP", address);
        }
        let response = match body {
            Some(json) => call
                .set("content-type", "application/json")
                .send_string(&json),
            None => call.call(),
        };
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(error) => panic!("the faucet could not be reached: {error}"),
        };
        let status = response.status();
        let retry_after = response
            .header("retry-after")
            .map(|value| value.to_string());
        let text = response.into_string().unwrap_or_default();
        let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
        (status, json, retry_after)
    })
    .await
    .expect("the request thread")
}

/// A real `qn1` address, made the way a wallet makes one.
fn an_address(tag: &str) -> String {
    let dir = tempdir::TempDir::new(tag);
    let seed = dir.path().join("seed");
    let key = qnero_wallet::keys::create_seed(&seed).expect("a spending key");
    key.address().encode()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_and_health_report_a_working_faucet() {
    let dir = tempdir::TempDir::new("cfg");
    let harness = start(config_in(dir.path())).await;

    let (status, body, _) = request("GET", format!("{}/status", harness.base), None, None).await;
    assert_eq!(status, 200);
    assert_eq!(body["configured"], serde_json::json!(true));
    assert_eq!(body["captchaEnabled"], serde_json::json!(false));
    assert_eq!(body["dripQuanta"], serde_json::json!(1_000));
    assert_eq!(body["dripQnr"], serde_json::json!("10"));
    assert_eq!(body["cooldownHours"], serde_json::json!(24.0));
    assert_eq!(body["chainHead"], serde_json::json!(42));
    assert_eq!(body["queued"], serde_json::json!(0));
    // Every amount comes back twice, which is what `README.md` promises a
    // reader of this API. The paid total is the one that had no QNR sibling,
    // so a probe reading it alone took 1000 for a thousand QNR.
    assert_eq!(body["balanceQuanta"], serde_json::json!(100_000));
    assert_eq!(body["balanceQnr"], serde_json::json!("1000"));
    assert_eq!(body["paidQuanta"], serde_json::json!(0));
    assert_eq!(body["paidQnr"], serde_json::json!("0"));

    let (status, body, _) = request("GET", format!("{}/health", harness.base), None, None).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], serde_json::json!("ok"));
    // And the balance the deployed monitor jq-selects out of this body, in
    // both spellings, so an alert reason can quote the one with a unit on it.
    assert_eq!(body["balanceQuanta"], serde_json::json!(100_000));
    assert_eq!(body["balanceQnr"], serde_json::json!("1000"));
}

/// A faucet that is up and cannot pay is an outage, and `/health` has to say
/// so: the whole point of the endpoint is that something pages on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_is_503_when_the_faucet_cannot_pay() {
    let dir = tempdir::TempDir::new("cfg");
    let harness = start(config_in(dir.path())).await;

    harness.shared.spendable_quanta.store(10, Ordering::Relaxed);
    let (status, body, _) = request("GET", format!("{}/health", harness.base), None, None).await;
    assert_eq!(status, 503);
    assert_eq!(body["funded"], serde_json::json!(false));

    // And a node that has not answered in six minutes, which at 120 s blocks
    // is three intervals and past any ordinary wait.
    harness
        .shared
        .spendable_quanta
        .store(100_000, Ordering::Relaxed);
    harness
        .shared
        .last_seen_node
        .store(now_secs() - 1_000, Ordering::Relaxed);
    let (status, body, _) = request("GET", format!("{}/health", harness.base), None, None).await;
    assert_eq!(status, 503);
    assert_eq!(body["nodeFresh"], serde_json::json!(false));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_claim_is_queued_and_reaches_the_worker() {
    let dir = tempdir::TempDir::new("cfg");
    let mut harness = start(config_in(dir.path())).await;
    let address = an_address("recipient");

    let (status, body, _) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(format!("{{\"address\":\"{address}\"}}")),
        Some("203.0.113.9"),
    )
    .await;
    assert_eq!(status, 202);
    assert_eq!(body["status"], serde_json::json!("queued"));
    assert_eq!(body["amountQuanta"], serde_json::json!(1_000));
    assert_eq!(body["amountQnr"], serde_json::json!("10"));
    let id = body["id"].as_i64().expect("a claim id");

    let job = harness
        .jobs
        .try_recv()
        .expect("the worker was handed the job");
    assert_eq!(job.claim_id, id);
    assert_eq!(job.quanta, 1_000);

    // And the claim is readable while it waits.
    let (status, body, _) = request("GET", format!("{}/drip/{id}", harness.base), None, None).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], serde_json::json!("queued"));

    // Once the worker settles it, the same route reports the block.
    harness
        .store
        .lock()
        .expect("the ledger")
        .mark_sent(id, 77, now_secs())
        .expect("mark sent");
    let (_, body, _) = request("GET", format!("{}/drip/{id}", harness.base), None, None).await;
    assert_eq!(body["status"], serde_json::json!("sent"));
    assert_eq!(body["includedAt"], serde_json::json!(77));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_string_that_is_not_an_address_touches_nothing() {
    let dir = tempdir::TempDir::new("cfg");
    let mut harness = start(config_in(dir.path())).await;

    for wanted in ["", "not-an-address", "qn1zzzz", "0x1234"] {
        let (status, body, retry_after) = request(
            "POST",
            format!("{}/drip", harness.base),
            Some(serde_json::json!({ "address": wanted }).to_string()),
            Some("203.0.113.9"),
        )
        .await;
        assert_eq!(status, 400, "{wanted:?} was not refused as a bad address");
        assert_eq!(body["reason"], serde_json::json!("bad-address"));
        assert!(
            retry_after.is_none(),
            "a malformed address is not a rate limit"
        );
    }
    assert!(
        harness.jobs.try_recv().is_err(),
        "a bad address reached the worker"
    );
    assert_eq!(
        harness
            .store
            .lock()
            .expect("the ledger")
            .queued_claims()
            .expect("queued")
            .len(),
        0,
        "a bad address wrote a row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_address_gets_one_drip_per_cooldown() {
    let dir = tempdir::TempDir::new("cfg");
    let harness = start(config_in(dir.path())).await;
    let address = an_address("twice");
    let body = serde_json::json!({ "address": address }).to_string();

    let (status, _, _) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(body.clone()),
        Some("203.0.113.9"),
    )
    .await;
    assert_eq!(status, 202);

    // A different client, so the address limit is what answers this one.
    let (status, refusal, retry_after) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(body),
        Some("198.51.100.4"),
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(refusal["reason"], serde_json::json!("address-cooldown"));
    assert_eq!(retry_after.as_deref(), Some("86400"));
}

/// bech32m lowercases the human-readable part and maps `A-Z` onto the same
/// values as `a-z`, so the shouted spelling of an address is the same account.
/// The ledger is a `TEXT` column with binary collation, so a cooldown keyed on
/// what was posted gives that one account two drips.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_recipient_cannot_spell_its_way_to_a_second_drip() {
    let dir = tempdir::TempDir::new("cfg");
    let harness = start(config_in(dir.path())).await;
    let address = an_address("shouted");
    let shouted = address.to_uppercase();
    assert_ne!(shouted, address, "the test needs two spellings");

    let (status, body, _) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(serde_json::json!({ "address": address }).to_string()),
        Some("203.0.113.9"),
    )
    .await;
    assert_eq!(status, 202);
    assert_eq!(
        body["address"],
        serde_json::json!(address),
        "the canonical spelling is what is recorded and answered"
    );

    // A different client, so the address limit is the one that can answer.
    let (status, refusal, _) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(serde_json::json!({ "address": shouted }).to_string()),
        Some("198.51.100.4"),
    )
    .await;
    assert_eq!(status, 429, "the shouted spelling is the same recipient");
    assert_eq!(refusal["reason"], serde_json::json!("address-cooldown"));
}

/// Eight claims for one address, posted together from eight clients. The
/// limits are read and the row is written under one lock hold, so exactly one
/// of them is accepted. Reading the limits, releasing the lock and inserting
/// afterwards lets every request in the batch see a ledger none of them has
/// written to yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simultaneous_claims_for_one_address_produce_one_drip() {
    let dir = tempdir::TempDir::new("cfg");
    let mut harness = start(config_in(dir.path())).await;
    let address = an_address("stampede");
    let clients = [
        "203.0.113.1",
        "203.0.113.2",
        "203.0.113.3",
        "203.0.113.4",
        "203.0.113.5",
        "203.0.113.6",
        "203.0.113.7",
        "203.0.113.8",
    ];

    let mut attempts = Vec::new();
    for client in clients {
        let body = serde_json::json!({ "address": address }).to_string();
        let url = format!("{}/drip", harness.base);
        attempts.push(tokio::spawn(async move {
            request("POST", url, Some(body), Some(client)).await
        }));
    }
    let mut accepted = 0;
    let mut refused = 0;
    for attempt in attempts {
        let (status, body, _) = attempt.await.expect("the request task");
        match status {
            202 => accepted += 1,
            429 => {
                assert_eq!(body["reason"], serde_json::json!("address-cooldown"));
                refused += 1;
            }
            other => panic!("unexpected status {other}: {body}"),
        }
    }
    assert_eq!(accepted, 1, "one address, one drip");
    assert_eq!(refused, clients.len() - 1);

    // And the queue holds exactly the one job.
    assert!(harness.jobs.try_recv().is_ok(), "the accepted claim");
    assert!(
        harness.jobs.try_recv().is_err(),
        "nothing else reached the worker"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_client_gets_its_allowance_and_no_more() {
    let dir = tempdir::TempDir::new("cfg");
    let mut config = config_in(dir.path());
    config.ip_limit = 2;
    let harness = start(config).await;

    for attempt in 0..2 {
        let address = an_address(&format!("client-{attempt}"));
        let (status, _, _) = request(
            "POST",
            format!("{}/drip", harness.base),
            Some(serde_json::json!({ "address": address }).to_string()),
            Some("203.0.113.9"),
        )
        .await;
        assert_eq!(status, 202, "claim {attempt} was refused");
    }

    let third = an_address("client-2");
    let (status, refusal, retry_after) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(serde_json::json!({ "address": third }).to_string()),
        Some("203.0.113.9"),
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(refusal["reason"], serde_json::json!("client-limit"));
    assert!(retry_after.is_some());

    // Another client is unaffected, which is what says the bucket is keyed on
    // the address nginx reported rather than being one global counter.
    let (status, _, _) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(serde_json::json!({ "address": third }).to_string()),
        Some("198.51.100.4"),
    )
    .await;
    assert_eq!(status, 202);
}

/// Refusing here is what stops a claim spending its requester's cooldown on a
/// drip that was always going to fail inside note selection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_drained_faucet_refuses_before_it_writes_a_row() {
    let dir = tempdir::TempDir::new("cfg");
    let mut harness = start(config_in(dir.path())).await;
    harness
        .shared
        .spendable_quanta
        .store(100, Ordering::Relaxed);
    let address = an_address("drained");

    let (status, refusal, _) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(serde_json::json!({ "address": address }).to_string()),
        Some("203.0.113.9"),
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(refusal["reason"], serde_json::json!("drained"));
    assert!(harness.jobs.try_recv().is_err());

    // The requester keeps their allowance: nobody was paid.
    harness
        .shared
        .spendable_quanta
        .store(100_000, Ordering::Relaxed);
    let (status, _, _) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(serde_json::json!({ "address": address }).to_string()),
        Some("203.0.113.9"),
    )
    .await;
    assert_eq!(status, 202);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turnstile_refuses_a_claim_with_no_token_before_it_calls_cloudflare() {
    let dir = tempdir::TempDir::new("cfg");
    let mut config = config_in(dir.path());
    config.turnstile_secret = Some("a-secret".into());
    config.turnstile_site_key = Some("a-site-key".into());
    let harness = start(config).await;
    let address = an_address("captcha");

    let (status, refusal, _) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(serde_json::json!({ "address": address }).to_string()),
        Some("203.0.113.9"),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(refusal["reason"], serde_json::json!("captcha-missing"));

    // And the page says the challenge is on, which is what an external
    // watchdog asserts against a production box.
    let (_, body, _) = request("GET", format!("{}/status", harness.base), None, None).await;
    assert_eq!(body["captchaEnabled"], serde_json::json!(true));
}

/// One prover, one drip at a time. Past the queue the honest answer is a 503
/// with a `Retry-After`, answered at once, rather than a request held open for
/// minutes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_is_a_503_and_not_a_wait() {
    let dir = tempdir::TempDir::new("cfg");
    let mut config = config_in(dir.path());
    config.queue_depth = 2;
    config.ip_limit = 100;
    let harness = start(config).await;

    for attempt in 0..2 {
        let address = an_address(&format!("queue-{attempt}"));
        let (status, _, _) = request(
            "POST",
            format!("{}/drip", harness.base),
            Some(serde_json::json!({ "address": address }).to_string()),
            Some("203.0.113.9"),
        )
        .await;
        assert_eq!(status, 202);
    }

    let address = an_address("queue-full");
    let (status, refusal, retry_after) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(serde_json::json!({ "address": address }).to_string()),
        Some("203.0.113.9"),
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(refusal["reason"], serde_json::json!("busy"));
    assert!(retry_after.is_some());

    // The row for the claim that could not be queued is failed rather than
    // left pending, so its requester can ask again rather than watching a
    // claim nothing will pick up.
    let queued = harness
        .store
        .lock()
        .expect("the ledger")
        .queued_claims()
        .expect("queued");
    assert_eq!(queued.len(), 2);
}

/// The page is served, with the three files beside it. The icon is one of
/// them: a browser asks this origin for `/favicon.svg`, and a 404 there is the
/// default globe beside a tab whose whole family shows an amber Q.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_page_and_its_three_files_are_served() {
    let dir = tempdir::TempDir::new("cfg");
    let harness = start(config_in(dir.path())).await;

    for path in ["/", "/app.css", "/app.js", "/favicon.svg"] {
        let (status, _, _) = request("GET", format!("{}{path}", harness.base), None, None).await;
        assert_eq!(status, 200, "{path} was not served");
    }
}

/// What the page's progress line reads its steps from.
///
/// One prover, one job at a time, so the claim at the head of the queue is
/// the one being proved and everything behind it is waiting for a prover. A
/// page with only a stopwatch says "proving, about 10 s" to somebody who is
/// fourth in line, which is a progress line that lies; `phase` and `ahead`
/// are what make the steps true, and they come from rows the ledger already
/// keeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_claim_knows_which_step_it_is_on() {
    let dir = tempdir::TempDir::new("cfg");
    let harness = start(config_in(dir.path())).await;

    let mut ids = Vec::new();
    for attempt in 0..2 {
        let (status, body, _) = request(
            "POST",
            format!("{}/drip", harness.base),
            Some(serde_json::json!({ "address": an_address(&format!("phase-{attempt}")) }).to_string()),
            Some("203.0.113.21"),
        )
        .await;
        assert_eq!(status, 202);
        ids.push(body["id"].as_i64().expect("a claim id"));
    }

    let (_, first, _) = request("GET", format!("{}/drip/{}", harness.base, ids[0]), None, None).await;
    assert_eq!(first["status"], serde_json::json!("queued"));
    assert_eq!(first["phase"], serde_json::json!("proving"));
    assert_eq!(first["ahead"], serde_json::json!(0));

    let (_, second, _) =
        request("GET", format!("{}/drip/{}", harness.base, ids[1]), None, None).await;
    assert_eq!(second["status"], serde_json::json!("queued"));
    assert_eq!(second["phase"], serde_json::json!("queued"));
    assert_eq!(second["ahead"], serde_json::json!(1));

    // `submitted_at` is written just before the payment goes to the node, so a
    // claim carrying one is in the pool waiting for a block rather than being
    // proved.
    harness
        .store
        .lock()
        .expect("the ledger")
        .mark_submitted(ids[0], now_secs())
        .expect("submitted");
    let (_, first, _) = request("GET", format!("{}/drip/{}", harness.base, ids[0]), None, None).await;
    assert_eq!(first["phase"], serde_json::json!("waiting"));
}

/// The per-client limit counts an IPv6 requester by its /64, through the whole
/// stack rather than in a unit test of the key function.
///
/// The address half of the limit is no help against this: a recipient address
/// is minted locally for nothing, so a requester who wants a second drip mints
/// a second address. The client half is the one that has to hold, and a client
/// holding an ordinary /64 has 2^64 addresses to rotate through. Three claims
/// go in from three addresses in one /64 and the fourth is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_ipv6_prefix_is_one_client() {
    let dir = tempdir::TempDir::new("cfg");
    let harness = start(config_in(dir.path())).await;

    for client in [
        "2001:db8:aa:bb:1:2:3:4",
        "2001:db8:aa:bb::99",
        "2001:db8:aa:bb:ffff:ffff:ffff:ffff",
    ] {
        let (status, body, _) = request(
            "POST",
            format!("{}/drip", harness.base),
            Some(serde_json::json!({ "address": an_address("v6") }).to_string()),
            Some(client),
        )
        .await;
        assert_eq!(status, 202, "{client} was refused: {body}");
    }

    let (status, refusal, retry_after) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(serde_json::json!({ "address": an_address("v6-fourth") }).to_string()),
        Some("2001:db8:aa:bb:dead:beef:dead:beef"),
    )
    .await;
    assert_eq!(status, 429, "a fourth address in the same /64 was served");
    assert_eq!(refusal["reason"], serde_json::json!("client-limit"));
    assert!(retry_after.is_some());

    // A different /64 is a different client, so the limit bounds a prefix
    // rather than the whole of IPv6.
    let (status, _, _) = request(
        "POST",
        format!("{}/drip", harness.base),
        Some(serde_json::json!({ "address": an_address("v6-elsewhere") }).to_string()),
        Some("2001:db8:aa:cc::1"),
    )
    .await;
    assert_eq!(status, 202, "another /64 was counted as the same client");
}

/// What a restart does with a claim that was already being paid.
///
/// The row is written before the proof and cleared after the send returns, so
/// a process that dies in between leaves a `queued` row whose payment may
/// already be in a block. Re-queueing it pays that address twice for one
/// crash, which is what `submitted_at` exists to prevent: an interrupted claim
/// is failed, and its cooldown is held because the faucet cannot tell a
/// payment that landed from one that did not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_claim_is_never_paid_twice() {
    let dir = tempdir::TempDir::new("recover");
    let db = dir.path().join("claims.sqlite");
    let key = dir.path().join("ip-hash.key");
    let store = Arc::new(Mutex::new(Store::open(&db, &key).expect("a ledger")));

    let untouched = an_address("untouched");
    let mid_flight = an_address("mid-flight");
    let (untouched_id, mid_flight_id) = {
        let ledger = store.lock().expect("the ledger");
        let hash = ledger.ip_hash("203.0.113.7");
        let first = ledger
            .record_queued(&untouched, &hash, 1_000, now_secs())
            .expect("insert");
        let second = ledger
            .record_queued(&mid_flight, &hash, 1_000, now_secs())
            .expect("insert");
        // The worker got as far as handing this one to the node.
        ledger
            .mark_submitted(second, now_secs())
            .expect("submitted");
        (first, second)
    };

    let (jobs_tx, mut jobs) = tokio::sync::mpsc::channel(8);
    qnero_faucet::worker::recover_queued_claims(&store, &jobs_tx).expect("recovery");

    let job = jobs.try_recv().expect("the untouched claim was re-queued");
    assert_eq!(job.claim_id, untouched_id);
    assert!(
        jobs.try_recv().is_err(),
        "the interrupted claim was queued to be proved a second time"
    );

    let ledger = store.lock().expect("the ledger");
    let claim = ledger
        .claim(mid_flight_id)
        .expect("query")
        .expect("the row is still there");
    assert_eq!(claim.status.as_str(), "failed");
    assert_eq!(claim.detail.as_deref(), Some("interrupted"));
    assert!(
        ledger
            .last_claim_for_address(&mid_flight)
            .expect("query")
            .is_some(),
        "an interrupted claim has to hold its cooldown, since it may have been paid"
    );
}
