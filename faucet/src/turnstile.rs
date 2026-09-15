//! Cloudflare Turnstile, the one outbound request this binary makes.
//!
//! Optional, behind `QNERO_FAUCET_TURNSTILE_SECRET`. A devnet run needs no
//! Cloudflare account and a public faucet should have one, so `/status`
//! reports `captchaEnabled` and the external watchdog asserts it is `true` on
//! the deployed box. What that assertion does not prove is named in the
//! runbook: a configured server is not the page carrying the matching site
//! key, nor Cloudflare accepting the domain.
//!
//! The call is blocking `ureq`, like everything else in this tree's RPC path,
//! so it runs on a blocking task. It is bounded by a timeout rather than left
//! to the default, because a claim waiting on Cloudflare holds a request slot.

use std::time::Duration;

use serde::Deserialize;

const SITEVERIFY: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Deserialize)]
struct Verdict {
    success: bool,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
}

/// Whether Cloudflare accepts this token for this secret.
///
/// A network failure is a refusal. A faucet that treats an unreachable
/// Cloudflare as a pass has no captcha for as long as the outage lasts, which
/// is exactly when somebody is likely to be draining it. The error is logged with its codes; the requester is told only that the
/// challenge was refused.
pub fn verify(secret: &str, token: &str, client: Option<&str>) -> bool {
    let agent = ureq::AgentBuilder::new().timeout(TIMEOUT).build();
    let mut form: Vec<(&str, &str)> = vec![("secret", secret), ("response", token)];
    if let Some(address) = client {
        form.push(("remoteip", address));
    }
    let response = match agent.post(SITEVERIFY).send_form(&form) {
        Ok(response) => response,
        Err(error) => {
            eprintln!("turnstile: siteverify could not be reached, refusing the claim: {error}");
            return false;
        }
    };
    match response.into_json::<Verdict>() {
        Ok(verdict) if verdict.success => true,
        Ok(verdict) => {
            eprintln!("turnstile: refused, codes {:?}", verdict.error_codes);
            false
        }
        Err(error) => {
            eprintln!("turnstile: siteverify answered something this cannot read: {error}");
            false
        }
    }
}
