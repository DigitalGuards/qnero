/*
 * The faucet page's whole script.
 *
 * It posts one claim and then polls it, because a drip is a proof: about ten
 * seconds to prove and up to one 120 s block to settle. The server answers the
 * POST as soon as the claim is queued, so nothing here holds a request open
 * across the proof.
 *
 * What the reader sees of that wait is the progress line inside the panel. The
 * steps are the server's own `phase`, which comes from rows the ledger already
 * keeps, so a claim that is fourth in a queue says queued rather than claiming
 * to be proving. A server too old to send one falls back to the stopwatch.
 */
'use strict';

const form = document.getElementById('form');
const address = document.getElementById('address');
const check = document.getElementById('check');
const submit = document.getElementById('submit');
const result = document.getElementById('result');
const status = document.getElementById('status');
const bar = document.getElementById('bar');
const panelBody = document.getElementById('body');
const progress = document.getElementById('progress');
const steps = [...document.querySelectorAll('.steps li')];
const elapsed = document.getElementById('elapsed');
const expect = document.getElementById('expect');
const receipt = document.getElementById('receipt');
const receiptLine = document.getElementById('receipt-line');
const again = document.getElementById('again');

/** How often to ask what became of a claim, and for how long. */
const POLL_MS = 3000;
const POLL_LIMIT_MS = 5 * 60 * 1000;

/** The steps, in the order a claim passes through them. */
const PHASES = ['queued', 'proving', 'waiting', 'sent'];

/** True from the press until the claim settles, fails or stops being polled. */
let claimInFlight = false;
let ticking = 0;

/*
 * The one line that changes, under the button. An error is announced at once
 * and everything else politely, which is why the role moves with the message
 * rather than being fixed in the markup.
 */
function say(text, kind) {
  result.hidden = text === '';
  result.textContent = text;
  result.className = kind ? `result result--${kind}` : 'result';
  result.setAttribute('role', kind === 'bad' ? 'alert' : 'status');
  result.setAttribute('aria-live', kind === 'bad' ? 'assertive' : 'polite');
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
  if (claimInFlight || !receipt.hidden) return;
  submit.disabled = !canPay;
  if (!canPay) {
    say('The faucet is empty. The operator has to refill it.', 'bad');
  } else if (result.textContent.startsWith('The faucet is empty')) {
    say('', null);
  }
}

/** `qn1q84a…lcge2v, 2571 characters`: what the field is actually holding. */
function describeAddress(value) {
  if (!value) return '';
  const short = value.length > 20 ? `${value.slice(0, 7)}…${value.slice(-6)}` : value;
  return `${short}, ${value.length} characters`;
}

/** `0:42`, in the tabular figures the whole page sets numbers in. */
function clock(milliseconds) {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

/*
 * The step a claim is on, and the sentence that goes with it.
 *
 * The explanation of the wait lives here and nowhere else on the page: it is
 * read while the wait is happening, by somebody who now has a reason to care
 * what a private payment costs.
 */
function showPhase(phase, ahead) {
  const at = PHASES.indexOf(phase);
  for (const step of steps) {
    const mine = PHASES.indexOf(step.dataset.phase);
    step.dataset.state = mine < at ? 'done' : mine === at ? 'now' : 'next';
  }
  if (phase === 'queued') {
    if (ahead === 0) expect.textContent = 'The faucet has your claim.';
    else if (ahead === 1) expect.textContent = '1 claim ahead of yours, about 30 s.';
    else expect.textContent = `${ahead} claims ahead of yours, about 30 s each.`;
  } else if (phase === 'proving') {
    expect.textContent =
      'Every payment on Qnero is private, and a private payment is a zero-knowledge proof. ' +
      'The faucet proves one at a time.';
  } else if (phase === 'waiting') {
    expect.textContent = 'The payment is with the node. It settles in the next block.';
  }
}

/** What a server that sends no `phase` looks like from a stopwatch. */
function phaseOf(body, sinceStart) {
  if (typeof body.phase === 'string') return body.phase;
  if (sinceStart < 2000) return 'queued';
  if (sinceStart < 14000) return 'proving';
  return 'waiting';
}

function startWorking(startedAt) {
  claimInFlight = true;
  submit.disabled = true;
  submit.textContent = 'Working';
  progress.hidden = false;
  bar.hidden = false;
  say('', null);
  clearInterval(ticking);
  elapsed.textContent = '0:00';
  ticking = setInterval(() => {
    elapsed.textContent = clock(Date.now() - startedAt);
  }, 1000);
}

function stopWorking() {
  claimInFlight = false;
  clearInterval(ticking);
  bar.hidden = true;
  submit.textContent = 'Request funds';
}

/*
 * The end of a claim: one line, one primary, and one quiet way back to an
 * empty form. The form body goes with it, so the button cannot re-arm itself
 * over an address the server has just paid and would now refuse.
 */
function showReceipt(line) {
  stopWorking();
  progress.hidden = true;
  panelBody.hidden = true;
  receiptLine.textContent = line;
  receipt.hidden = false;
  say('', null);
}

again.addEventListener('click', () => {
  receipt.hidden = true;
  panelBody.hidden = false;
  address.value = '';
  address.removeAttribute('aria-invalid');
  address.removeAttribute('aria-describedby');
  check.hidden = true;
  check.textContent = '';
  submit.disabled = false;
  address.focus();
  refreshStatus();
});

async function poll(id, startedAt) {
  const response = await fetch(`/drip/${id}`, { headers: { accept: 'application/json' } });
  const body = await response.json();
  if (body.status === 'sent') {
    showPhase('sent', 0);
    showReceipt(
      `Sent ${body.amountQnr} QNR in block ${body.includedAt}. It shows in Qloak after the ` +
        'next sync.',
    );
    refreshStatus();
    return;
  }
  if (body.status === 'failed') {
    stopWorking();
    progress.hidden = true;
    // No automatic retry here, and deliberately: a retry is another claim, and
    // a claim that settled after the page gave up on it would spend the
    // address's cooldown on a payment nobody watched.
    submit.textContent = 'Try again';
    submit.disabled = false;
    say(`The drip did not settle (${body.reason}). Try again in a few minutes.`, 'bad');
    return;
  }
  if (Date.now() - startedAt > POLL_LIMIT_MS) {
    showReceipt(
      'Still working. Your claim is queued and will settle on its own. Sync your wallet in a ' +
        'few minutes.',
    );
    return;
  }
  showPhase(phaseOf(body, Date.now() - startedAt), body.ahead || 0);
  setTimeout(() => {
    poll(id, startedAt).catch(lostContact);
  }, POLL_MS);
}

function lostContact() {
  stopWorking();
  progress.hidden = true;
  submit.textContent = 'Try again';
  submit.disabled = false;
  say('Lost contact with the faucet while waiting.', 'bad');
}

/*
 * An address carries no whitespace, so any that arrives came from a copy that
 * wrapped, and dropping it here is what makes a paste out of a terminal work.
 * The value is rewritten only when it actually changed, so typing keeps its
 * caret.
 */
address.addEventListener('input', () => {
  const clean = address.value.replace(/\s+/g, '');
  if (clean !== address.value) address.value = clean;
  check.textContent = describeAddress(clean);
  check.hidden = clean === '';
  address.removeAttribute('aria-invalid');
  address.removeAttribute('aria-describedby');
});

/*
 * Enter sends. A textarea takes the key as a newline and the form is never
 * submitted, which is the cost of the three rows; `enterkeyhint="send"` says
 * send on a phone keyboard and this is what makes it true.
 */
address.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    form.requestSubmit();
  }
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const wanted = address.value.trim();
  if (!wanted) return;
  const startedAt = Date.now();
  startWorking(startedAt);
  showPhase('queued', 0);
  try {
    const response = await fetch('/drip', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: wanted, turnstileToken: turnstileToken() }),
    });
    const body = await response.json();
    if (!response.ok) {
      stopWorking();
      progress.hidden = true;
      submit.disabled = false;
      if (body.reason === 'bad-address') {
        address.setAttribute('aria-invalid', 'true');
        address.setAttribute('aria-describedby', 'result');
      }
      say(body.message || 'The faucet refused that request.', 'bad');
      return;
    }
    poll(body.id, startedAt).catch(lostContact);
  } catch (error) {
    stopWorking();
    progress.hidden = true;
    submit.disabled = false;
    say('The faucet could not be reached.', 'bad');
  }
});

retargetLinks();
refreshStatus();
