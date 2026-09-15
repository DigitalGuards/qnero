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

function say(text, kind) {
  result.textContent = text;
  result.className = kind ? `result result--${kind}` : 'result';
}

function turnstileToken() {
  const field = document.querySelector('input[name="cf-turnstile-response"]');
  return field ? field.value : '';
}

async function refreshStatus() {
  try {
    const response = await fetch('/status', { headers: { accept: 'application/json' } });
    if (!response.ok) return;
    const body = await response.json();
    const parts = [];
    if (typeof body.chainHead === 'number') parts.push(`chain head ${body.chainHead}`);
    if (typeof body.balanceQnr === 'string') parts.push(`${body.balanceQnr} QNR left`);
    if (typeof body.queued === 'number' && body.queued > 0) {
      parts.push(`${body.queued} claim(s) waiting`);
    }
    status.textContent = parts.join(' · ');
  } catch (error) {
    /* A status line that cannot be fetched is a status line that stays empty. */
  }
}

async function poll(id, startedAt) {
  const response = await fetch(`/drip/${id}`, { headers: { accept: 'application/json' } });
  const body = await response.json();
  if (body.status === 'sent') {
    say(
      `Sent. ${body.amountQnr} QNR settled in block ${body.includedAt}. Sync your wallet to see ` +
        'the note.',
      'ok',
    );
    submit.disabled = false;
    refreshStatus();
    return;
  }
  if (body.status === 'failed') {
    say(`The drip did not settle (${body.reason}). Try again in a few minutes.`, 'bad');
    submit.disabled = false;
    return;
  }
  if (Date.now() - startedAt > POLL_LIMIT_MS) {
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
      say('Lost contact with the faucet while waiting.', 'bad');
      submit.disabled = false;
    });
  }, POLL_MS);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const wanted = address.value.trim();
  if (!wanted) return;
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
      say(body.message || 'The faucet refused that request.', 'bad');
      submit.disabled = false;
      return;
    }
    poll(body.id, Date.now()).catch(() => {
      say('Lost contact with the faucet while waiting.', 'bad');
      submit.disabled = false;
    });
  } catch (error) {
    say('The faucet could not be reached.', 'bad');
    submit.disabled = false;
  }
});

refreshStatus();
