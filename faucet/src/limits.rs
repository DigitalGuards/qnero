//! What a claim is refused for, decided cheapest first.
//!
//! The order is the point. Every step below costs more than the one above it,
//! and the last of them holds a spend key, so a claim that is going to be
//! refused should be refused as far up this list as it can be:
//!
//! 1. the address decodes (no state touched, no round trip),
//! 2. the per-address cooldown (one indexed read),
//! 3. the per-client-address window (one indexed read),
//! 4. the faucet has funds to pay (one cached number),
//! 5. Turnstile (one outbound HTTPS request),
//! 6. the queue has room (one channel),
//! 7. the proof (ten seconds and about a gigabyte).
//!
//! Turnstile sits below the two rate limits deliberately: a client that has
//! already had its drips today is refused without Cloudflare being asked
//! anything about it.

use std::time::Duration;

/// Why a claim was refused. The strings are reason codes for the page and for
/// the ledger, so none of them carries a node URL, a seed path or an
/// extrinsic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The address is not a `qn1` Qnero address.
    BadAddress(String),
    /// This address has already been paid inside the cooldown.
    AddressCooldown { retry_after: Duration },
    /// This client has had its allowance inside the window.
    ClientLimit { limit: u32, retry_after: Duration },
    /// The faucet is below its floor. Nothing about the requester.
    Drained,
    /// Turnstile is on and the request carried no token.
    CaptchaMissing,
    /// Turnstile refused the token.
    CaptchaRefused,
    /// Every prover slot is taken.
    Busy { retry_after: Duration },
}

impl Refusal {
    /// The reason code. One word, stable, safe to log and to show.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadAddress(_) => "bad-address",
            Self::AddressCooldown { .. } => "address-cooldown",
            Self::ClientLimit { .. } => "client-limit",
            Self::Drained => "drained",
            Self::CaptchaMissing => "captcha-missing",
            Self::CaptchaRefused => "captcha-refused",
            Self::Busy { .. } => "busy",
        }
    }

    /// The HTTP status. A rate limit is 429, a captcha failure is 403, a
    /// malformed address is 400, and a faucet with nothing left or no prover
    /// free is 503, because both of those are the server's condition and not
    /// the request's.
    pub fn status(&self) -> u16 {
        match self {
            Self::BadAddress(_) => 400,
            Self::AddressCooldown { .. } | Self::ClientLimit { .. } => 429,
            Self::CaptchaMissing | Self::CaptchaRefused => 403,
            Self::Drained | Self::Busy { .. } => 503,
        }
    }

    /// Seconds for a `Retry-After` header, where one is honest.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::AddressCooldown { retry_after }
            | Self::ClientLimit { retry_after, .. }
            | Self::Busy { retry_after } => Some(retry_after.as_secs().max(1)),
            _ => None,
        }
    }

    /// What the requester is told. Plain, carrying no hint about anything the
    /// faucet holds, and written as sentences.
    ///
    /// The page prints these where they are read, under the button, so each
    /// one starts with a capital, ends with a full stop, and says what to do
    /// next where there is anything to do. They used to start lower case mid
    /// sentence, which reads as a template with a piece missing.
    pub fn message(&self) -> String {
        match self {
            Self::BadAddress(why) => {
                format!("Not a valid Qnero address: {why}. Paste it again, whole.")
            }
            Self::AddressCooldown { retry_after } => format!(
                "This address has already been paid. It can claim again in {}.",
                human(*retry_after)
            ),
            Self::ClientLimit { limit, retry_after } => format!(
                "This connection has had its {limit} claims. It can claim again in {}.",
                human(*retry_after)
            ),
            Self::Drained => {
                "The faucet is empty. The operator has to refill it.".to_string()
            }
            Self::CaptchaMissing => "The challenge was not completed.".to_string(),
            Self::CaptchaRefused => "The challenge was refused.".to_string(),
            Self::Busy { .. } => {
                "Every proving slot is busy. Try again in a minute.".to_string()
            }
        }
    }
}

fn human(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 7200 {
        format!("{} hours", seconds / 3600)
    } else if seconds >= 120 {
        format!("{} minutes", seconds / 60)
    } else {
        format!("{} seconds", seconds.max(1))
    }
}

/// Is this address inside its cooldown, and for how much longer.
pub fn address_cooldown(last_claim: Option<u64>, cooldown: Duration, now: u64) -> Option<Refusal> {
    let last = last_claim?;
    let elapsed = now.saturating_sub(last);
    if elapsed >= cooldown.as_secs() {
        return None;
    }
    Some(Refusal::AddressCooldown {
        retry_after: Duration::from_secs(cooldown.as_secs() - elapsed),
    })
}

/// Has this client address had its allowance inside the window.
pub fn client_limit(claims_in_window: u32, limit: u32, window: Duration) -> Option<Refusal> {
    if claims_in_window < limit {
        return None;
    }
    Some(Refusal::ClientLimit {
        limit,
        // Without the oldest row's timestamp this is the window itself, which
        // is the largest honest answer rather than a guess at the smallest.
        retry_after: window,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_address_is_not_on_cooldown() {
        assert_eq!(
            address_cooldown(None, Duration::from_secs(86_400), 1_000),
            None
        );
    }

    #[test]
    fn an_address_inside_the_cooldown_is_told_how_long_is_left() {
        let refusal = address_cooldown(Some(1_000), Duration::from_secs(3_600), 2_000)
            .expect("inside the cooldown");
        assert_eq!(
            refusal,
            Refusal::AddressCooldown {
                retry_after: Duration::from_secs(2_600)
            }
        );
        assert_eq!(refusal.status(), 429);
        assert_eq!(refusal.retry_after(), Some(2_600));
    }

    #[test]
    fn the_cooldown_ends_exactly_at_its_length() {
        let cooldown = Duration::from_secs(3_600);
        assert!(address_cooldown(Some(1_000), cooldown, 4_599).is_some());
        assert_eq!(address_cooldown(Some(1_000), cooldown, 4_600), None);
    }

    /// A clock that went backwards must not hand out a free claim or a
    /// negative wait. `saturating_sub` is what makes the elapsed time zero,
    /// which reads as the full cooldown still to run.
    #[test]
    fn a_clock_that_went_backwards_does_not_open_the_faucet() {
        let refusal = address_cooldown(Some(5_000), Duration::from_secs(3_600), 1_000)
            .expect("a claim from the future is still a claim");
        assert_eq!(
            refusal,
            Refusal::AddressCooldown {
                retry_after: Duration::from_secs(3_600)
            }
        );
    }

    #[test]
    fn a_client_is_refused_at_its_limit_and_not_before() {
        let window = Duration::from_secs(86_400);
        assert_eq!(client_limit(0, 3, window), None);
        assert_eq!(client_limit(2, 3, window), None);
        assert!(client_limit(3, 3, window).is_some());
        assert!(client_limit(9, 3, window).is_some());
    }

    /// Every refusal reaches the requester, so none of them may name anything
    /// the faucet holds.
    #[test]
    fn no_refusal_names_a_path_a_url_or_a_key() {
        let refusals = [
            Refusal::BadAddress("the checksum does not match".into()),
            Refusal::AddressCooldown {
                retry_after: Duration::from_secs(60),
            },
            Refusal::ClientLimit {
                limit: 3,
                retry_after: Duration::from_secs(60),
            },
            Refusal::Drained,
            Refusal::CaptchaMissing,
            Refusal::CaptchaRefused,
            Refusal::Busy {
                retry_after: Duration::from_secs(30),
            },
        ];
        for refusal in refusals {
            let text = format!("{} {}", refusal.code(), refusal.message());
            for forbidden in ["/var/lib", "/etc/qnero", "http://", "seed", "0x"] {
                assert!(
                    !text.contains(forbidden),
                    "the refusal {:?} says {forbidden:?}: {text}",
                    refusal.code()
                );
            }
        }
    }

    /// The page prints these under the button exactly as they arrive, so each
    /// one has to be a sentence: a capital at the front and a full stop at the
    /// end. A message that starts lower case reads as a template with a piece
    /// missing, which is how this page rendered every refusal it had.
    #[test]
    fn every_refusal_is_a_sentence() {
        let refusals = [
            Refusal::BadAddress("the checksum does not match".into()),
            Refusal::AddressCooldown {
                retry_after: Duration::from_secs(86_400),
            },
            Refusal::ClientLimit {
                limit: 3,
                retry_after: Duration::from_secs(86_400),
            },
            Refusal::Drained,
            Refusal::CaptchaMissing,
            Refusal::CaptchaRefused,
            Refusal::Busy {
                retry_after: Duration::from_secs(30),
            },
        ];
        for refusal in refusals {
            let message = refusal.message();
            let first = message.chars().next().expect("a message");
            assert!(
                first.is_uppercase(),
                "{:?} starts lower case: {message}",
                refusal.code()
            );
            assert!(
                message.ends_with('.'),
                "{:?} has no full stop: {message}",
                refusal.code()
            );
        }
    }

    #[test]
    fn durations_read_as_words() {
        assert_eq!(human(Duration::from_secs(30)), "30 seconds");
        assert_eq!(human(Duration::from_secs(600)), "10 minutes");
        assert_eq!(human(Duration::from_secs(86_400)), "24 hours");
    }
}
