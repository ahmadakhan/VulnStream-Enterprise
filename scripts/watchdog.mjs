#!/usr/bin/env node
/**
 * External watchdog for "the system should always be on".
 *
 * Prometheus cannot detect a total outage: if the monitored system and the
 * collector are both down, no rule evaluates and nothing fires. This script is
 * the out-of-band check for exactly that case. Run it from cron or a systemd
 * timer on a host that is NOT the one running VulnStream, so it survives the
 * failure it is watching for:
 *
 *   WATCHDOG_URL=https://vulnstream.example.com/live \
 *   WATCHDOG_ALERT_WEBHOOK=https://hooks.example.com/... \
 *   node /opt/vulnstream/scripts/watchdog.mjs
 *
 * Schedule it every two minutes from cron (first field: star-slash-2), on a
 * host that is not the one running VulnStream.
 *
 * It alerts only on a state CHANGE or on a sustained outage, never once per
 * run, so a long outage does not produce an alert on every invocation. It exits
 * non-zero when unhealthy, so cron/mail-on-failure also reports it.
 *
 * No secrets are printed. The URL and webhook are treated as credentials.
 */

const url = process.env.WATCHDOG_URL || '';
const webhook = process.env.WATCHDOG_ALERT_WEBHOOK || '';
const timeoutMs = Number(process.env.WATCHDOG_TIMEOUT_MS || 10000);
const stateFile = process.env.WATCHDOG_STATE_FILE || '/tmp/vulnstream-watchdog.state';
const reAlertAfterMs = Number(process.env.WATCHDOG_REALERT_MS || 30 * 60 * 1000);

if (!url) {
  console.error(JSON.stringify({ level: 'error', event: 'watchdog.misconfigured', reason: 'WATCHDOG_URL is required' }));
  process.exit(2);
}

async function check() {
  const started = Date.now();
  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    return { ok: response.ok, status: response.status, latencyMs: Date.now() - started };
  } catch (error) {
    // Distinguish "the process answered but is unhealthy" from "nothing answered".
    return { ok: false, status: 0, latencyMs: Date.now() - started, error: error?.name || 'FETCH_FAILED' };
  }
}

async function readState() {
  try {
    const { readFile } = await import('node:fs/promises');
    return JSON.parse(await readFile(stateFile, 'utf8'));
  } catch {
    return { healthy: true, lastAlertAt: 0 };
  }
}

async function writeState(state) {
  try {
    const { writeFile } = await import('node:fs/promises');
    await writeFile(stateFile, JSON.stringify(state), { mode: 0o600 });
  } catch {
    // A watchdog that cannot persist its state still alerts; it may repeat.
  }
}

async function alert(kind, detail) {
  if (!webhook) {
    // Always emit to stdout so the cron mail / log collector carries it even
    // when no webhook is configured.
    console.log(JSON.stringify({ level: 'critical', event: `watchdog.${kind}`, ...detail }));
    return;
  }
  try {
    await fetch(webhook, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        // Generic shape; adapt to the provider (PagerDuty Events, Slack, etc.).
        source: 'vulnstream-watchdog',
        status: kind === 'recovered' ? 'resolved' : 'firing',
        summary:
          kind === 'recovered'
            ? 'VulnStream watchdog: service reachable again'
            : 'VulnStream watchdog: service is DOWN',
        detail,
        at: new Date().toISOString(),
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    console.error(JSON.stringify({ level: 'critical', event: 'watchdog.delivery_failed' }));
  }
}

const result = await check();
const state = await readState();
const now = Date.now();

if (!result.ok) {
  // Alert on the transition, then at most every reAlertAfterMs while it persists.
  const dueForRealert = now - (state.lastAlertAt || 0) >= reAlertAfterMs;
  if (state.healthy !== false || dueForRealert) {
    await alert('down', { status: result.status, latencyMs: result.latencyMs, error: result.error });
    await writeState({ healthy: false, lastAlertAt: now, since: state.healthy === false ? state.since : now });
  }
  process.exitCode = 1;
} else {
  if (state.healthy === false) {
    const downForMs = state.since ? now - state.since : null;
    await alert('recovered', { latencyMs: result.latencyMs, downForMs });
    await writeState({ healthy: true, lastAlertAt: state.lastAlertAt || 0 });
  }
}
