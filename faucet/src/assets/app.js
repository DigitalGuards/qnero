/*
 * The faucet page's whole script.
 *
 * It posts one claim and then polls it, because a drip is a proof: about ten
 * seconds to prove and up to one 120 s block to settle. The server answers the
 * POST as soon as the claim is queued, so nothing here holds a request open
 * across the proof.
 */
'use strict';

const form = document.getElementById('form');
const address = document.getElementById('address');
const submit = document.getElementById('submit');
const result = document.getElementById('result');
const status = document.getElementById('status');

/** How often to ask what became of a claim, and for how long. */
const POLL_MS = 3000;
const POLL_LIMIT_MS = 5 * 60 * 1000;

/** True from the press until the claim settles, fails or stops being polled. */
let claimInFlight = false;

function say(text, kind) {
  result.textContent = text;
  result.className = kind ? `result result--${kind}` : 'result';
}

/*
 * The links out of this page, pointed at the deployment serving it.
 *
 * The markup carries the project's own hosts, so a reader with no script still
 * has somewhere to go, and this rewrites them when the page is served from
 * some other `faucet.<domain>`. Reading the hostname off `location` is what
 * keeps a second deployment from linking to the first one's wallet.
 */
function retargetLinks() {
  const match = /^faucet\.(.+)$/.exec(location.hostname);
  if (!match) return;
  const domain = match[1];
  for (const link of document.querySelectorAll('[data-host]')) {
    const sub = link.dataset.host;
    link.href = `https://${sub ? `${sub}.` : ''}${domain}/`;
  }
}

function turnstileToken() {
  const field = document.querySelector('input[name="cf-turnstile-response"]');
  return field ? field.value : '';
}

/** How many whole drips the faucet's balance is still good for. */
function dripsLeft(body) {
  if (typeof body.balanceQuanta !== 'number' || !body.dripQuanta) return null;
  return Math.floor(body.balanceQuanta / body.dripQuanta);
}

/*
 * The line under the h1: block, balance, drips left, and the queue when there
 * is one. "chain head" was node vocabulary in the one place this page shows
 * numbers, and a balance in QNR says nothing about how many claims are left in
 * it, which is the figure a reader is actually asking for.
 */
async function refreshStatus() {
  try {
    const response = await fetch('/status', { headers: { accept: 'application/json' } });
    if (!response.ok) return;
    const body = await response.json();
    const parts = [];
    if (typeof body.chainHead === 'number') parts.push(`Block ${body.chainHead}`);
    if (typeof body.balanceQnr === 'string') parts.push(`${body.balanceQnr} QNR in the faucet`);
    const left = dripsLeft(body);
    if (left !== null && left > 0) parts.push(left === 1 ? '1 drip left' : `${left} drips left`);
    if (typeof body.queued === 'number' && body.queued > 0) {
      parts.push(
        body.queued === 1
          ? '1 claim waiting, about 30 s'
          : `${body.queued} claims waiting, about 30 s each`,
      );
    }
    status.textContent = parts.join(' · ');
    if (left !== null) showWhetherItCanPay(left > 0);
  } catch (error) {
    /* A status line that cannot be fetched is a status line that stays empty. */
  }
}

/*
 * A drained faucet refuses every claim, and a reader used to discover that by
 * spending a paste and a press on it. The button is disabled up front instead,
 * with the sentence that says why, and nothing here touches a claim that is
 * already running.
 */
function showWhetherItCanPay(canPay) {
  if (claimInFlight) return;
  submit.disabled = !canPay;
  if (!canPay) {
    say('The faucet is empty. The operator has to refill it.', 'bad');
  } else if (result.textContent.startsWith('The faucet is empty')) {
    say('', null);
  }
}

async function poll(id, startedAt) {
  const response = await fetch(`/drip/${id}`, { headers: { accept: 'application/json' } });
  const body = await response.json();
  if (body.status === 'sent') {
    claimInFlight = false;
    say(
      `Sent. ${body.amountQnr} QNR settled in block ${body.includedAt}. Sync your wallet to see ` +
        'the funds.',
      'ok',
    );
    submit.disabled = false;
    refreshStatus();
    return;
  }
  if (body.status === 'failed') {
    claimInFlight = false;
    say(`The drip did not settle (${body.reason}). Try again in a few minutes.`, 'bad');
    submit.disabled = false;
    return;
  }
  if (Date.now() - startedAt > POLL_LIMIT_MS) {
    claimInFlight = false;
    say(
      `Still waiting. Claim ${id} is queued; the page stopped polling, the faucet did not stop ` +
        'working.',
      null,
    );
    submit.disabled = false;
    return;
  }
  say('Proving and waiting for a block. This takes a couple of minutes.', null);
  setTimeout(() => {
    poll(id, startedAt).catch(() => {
      claimInFlight = false;
      say('Lost contact with the faucet while waiting.', 'bad');
      submit.disabled = false;
    });
  }, POLL_MS);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const wanted = address.value.trim();
  if (!wanted) return;
  claimInFlight = true;
  submit.disabled = true;
  say('Asking...', null);
  try {
    const response = await fetch('/drip', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: wanted, turnstileToken: turnstileToken() }),
    });
    const body = await response.json();
    if (!response.ok) {
      claimInFlight = false;
      say(body.message || 'The faucet refused that request.', 'bad');
      submit.disabled = false;
      return;
    }
    poll(body.id, Date.now()).catch(() => {
      claimInFlight = false;
      say('Lost contact with the faucet while waiting.', 'bad');
      submit.disabled = false;
    });
  } catch (error) {
    claimInFlight = false;
    say('The faucet could not be reached.', 'bad');
    submit.disabled = false;
  }
});

retargetLinks();
refreshStatus();
