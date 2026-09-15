//! The one page this server serves, in the project site's type.
//!
//! Three files, none of them inline, so the content policy the runbook writes
//! for `faucet.<domain>` can say `script-src 'self'` and mean it. The tokens
//! are `site/css/site.css`'s, copied rather than linked because the faucet is
//! its own origin and a cross-origin stylesheet would be one more request and
//! one more thing to get wrong in a policy.
//!
//! The Turnstile widget is the one third-party element, and it appears only
//! when a site key is configured. With no key the page has no outbound
//! request at all.

use crate::config::Config;

pub const APP_CSS: &str = include_str!("assets/app.css");
pub const APP_JS: &str = include_str!("assets/app.js");
const INDEX: &str = include_str!("assets/index.html");

/// The page, with the parts that depend on configuration filled in.
pub fn index(config: &Config) -> String {
    let (widget, script) = match (&config.turnstile_site_key, config.captcha_enabled()) {
        (Some(key), true) => (
            format!(
                "<div class=\"cf-turnstile\" data-sitekey=\"{}\" data-theme=\"auto\"></div>",
                html_escape(key)
            ),
            "<script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\" async defer></script>"
                .to_string(),
        ),
        _ => (String::new(), String::new()),
    };
    INDEX
        .replace("<!--TURNSTILE_WIDGET-->", &widget)
        .replace("<!--TURNSTILE_SCRIPT-->", &script)
        .replace("<!--DRIP_QUANTA-->", &config.drip_quanta.to_string())
        .replace("<!--DRIP_QNR-->", &format_qnr(config.drip_quanta))
        .replace("<!--COOLDOWN-->", &format_hours(config.cooldown_hours()))
}

/// A count of pool steps as QNR, in the form a sentence wants.
///
/// Amounts move in steps of 0.01 QNR, so the whole precision is two decimal
/// places and the hundredths are dropped when they are zero: this page says
/// "10 QNR", which is how a person says it. The arithmetic is
/// [`qnero_wallet::units`]'s, so the faucet and the wallet round one way.
pub fn format_qnr(steps: u64) -> String {
    qnero_wallet::units::qnr_plain(steps)
}

fn format_hours(hours: f64) -> String {
    if (hours - hours.round()).abs() < 0.01 {
        let whole = hours.round() as i64;
        if whole == 1 {
            "hour".to_string()
        } else {
            format!("{whole} hours")
        }
    } else {
        format!("{hours:.1} hours")
    }
}

/// The three characters that could close an attribute or open an element.
/// The only value that reaches the page this way is the Turnstile site key,
/// which the operator configures, but a configured value is still a value.
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_read_as_qnr() {
        assert_eq!(format_qnr(1_000), "10");
        assert_eq!(format_qnr(1), "0.01");
        assert_eq!(format_qnr(1_234), "12.34");
        assert_eq!(format_qnr(0), "0");
    }

    #[test]
    fn hours_read_as_words() {
        assert_eq!(format_hours(24.0), "24 hours");
        assert_eq!(format_hours(1.0), "hour");
        assert_eq!(format_hours(0.5), "0.5 hours");
    }

    #[test]
    fn a_site_key_cannot_close_its_attribute() {
        assert_eq!(html_escape("a\"><script>"), "a&quot;&gt;&lt;script&gt;");
    }
}
