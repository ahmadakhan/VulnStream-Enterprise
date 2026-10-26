import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const deployDir = fileURLToPath(new URL('../deploy/', import.meta.url));

test('prometheus actually delivers alerts to an alertmanager', async () => {
  // Rules in vulnstream-alerts.yml were evaluated and discarded: prometheus.yml
  // had no alerting block, and Prometheus has no default receiver. An alert that
  // is never delivered is not an alert, which is why "if it is down, alert"
  // did not hold before this change.
  for (const file of ['prometheus.yml', 'prometheus-compose.yml']) {
    const yaml = await readFile(path.join(deployDir, 'monitoring', file), 'utf8');
    assert.match(yaml, /^alerting:/m, `${file} must configure alertmanagers`);
    assert.match(yaml, /alertmanager:9093/, `${file} must target the alertmanager service`);
    assert.match(yaml, /rule_files:/, `${file} must still load the rule file`);
  }
});

test('alertmanager has a route and every referenced receiver exists', async () => {
  const yaml = await readFile(path.join(deployDir, 'monitoring', 'alertmanager.yml'), 'utf8');
  assert.match(yaml, /^route:/m);
  assert.match(yaml, /repeat_interval:/, 'an ongoing outage must re-notify, not fire once');
  // A receiver name referenced by the route but not defined is a config that
  // fails to load at runtime -- i.e. no alerts, which is the bug being fixed.
  const defined = new Set([...yaml.matchAll(/^\s*-\s+name:\s*(\S+)\s*$/gm)].map((match) => match[1]));
  const referenced = new Set([...yaml.matchAll(/receiver:\s*(\S+)/g)].map((match) => match[1]));
  assert.ok(referenced.size > 0, 'the route must name a receiver');
  for (const name of referenced) assert.ok(defined.has(name), `receiver ${name} is referenced but not defined`);
});

test('alert rules only reference metrics the server exports', async () => {
  // A rule over a metric nobody exports is silent forever, which reads as
  // "healthy". Check each vulnstream_* metric against the exporter source.
  const rules = await readFile(path.join(deployDir, 'monitoring', 'vulnstream-alerts.yml'), 'utf8');
  const metricsSource = await readFile(
    fileURLToPath(new URL('../server/correlation/metrics.ts', import.meta.url)),
    'utf8',
  );
  const referenced = new Set([...rules.matchAll(/(vulnstream_[a-z_]+)/g)].map((match) => match[1]));
  assert.ok(referenced.size > 0);
  for (const metric of referenced)
    assert.ok(metricsSource.includes(metric), `alert rule uses ${metric}, which correlationMetrics does not export`);
});
