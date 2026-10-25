import { CorrelationOperations } from './CorrelationOperations';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, Database, Gauge, ShieldCheck, Terminal, Zap } from 'lucide-react';
import { useApp } from '../context/AppContext';
import type { CorrelationSnapshot } from '../../shared/correlation';
const sample = JSON.stringify({
  title: 'Kubernetes unpatched vulnerability actively exploited',
  content: 'Researchers report a zero-day vulnerability in k8s. Affected releases are under investigation.',
  url: 'https://example.org/security/kubernetes-early-warning',
});
export function CorrelationDashboard() {
  const { csrfToken, session } = useApp();
  const [snapshot, setSnapshot] = useState<CorrelationSnapshot | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [limit, setLimit] = useState(4);
  const [ndjson, setNdjson] = useState(sample);
  const [filter, setFilter] = useState('');
  const [busy, setBusy] = useState(false);
  const [follow, setFollow] = useState(true);
  const consoleRef = useRef<HTMLPreElement>(null);
  const canControl = session?.role === 'ADMIN' || session?.role === 'OPERATOR';
  useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    const controller = new AbortController();
    const refresh = async () => {
      try {
        const response = await fetch('/api/correlation', {
          credentials: 'same-origin',
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(5000)]),
        });
        if (!response.ok) throw new Error(`Telemetry unavailable (HTTP ${response.status})`);
        const data = (await response.json()) as CorrelationSnapshot;
        if (!disposed) {
          setSnapshot(data);
          setError('');
        }
      } catch (reason) {
        if (!disposed) setError(reason instanceof Error ? reason.message : 'Telemetry unavailable');
      } finally {
        if (!disposed) timer = setTimeout(() => void refresh(), 1000);
      }
    };
    void refresh();
    return () => {
      disposed = true;
      controller.abort();
      clearTimeout(timer);
    };
  }, []);
  useEffect(() => {
    if (follow && consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  }, [snapshot?.logs, follow]);
  const matches = useMemo(
    () =>
      (snapshot?.matches || []).filter((match) =>
        `${match.vendor} ${match.product} ${match.confidence} ${match.reason}`
          .toLowerCase()
          .includes(filter.toLowerCase()),
      ),
    [snapshot?.matches, filter],
  );
  const mutate = async (path: string, body: unknown) => {
    if (busy) return;
    setBusy(true);
    setNotice('');
    try {
      const response = await fetch(`/api/correlation/${path}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) throw new Error(`Action rejected (HTTP ${response.status})`);
      const result = (await response.json()) as { queued?: number };
      setNotice(result.queued !== undefined ? `${result.queued} records durably queued` : 'Control accepted');
    } catch (reason) {
      setNotice(reason instanceof Error ? reason.message : 'Action failed');
    } finally {
      setBusy(false);
    }
  };
  const metrics = [
    { label: 'Throughput', value: `${snapshot?.itemsPerSecond.toFixed(2) ?? '—'} items/s`, icon: Activity },
    { label: 'Memory / capacity', value: `${snapshot?.memoryPercent.toFixed(1) ?? '—'}%`, icon: Gauge },
    { label: 'Average ingestion', value: `${snapshot?.averageLatencyMs.toFixed(1) ?? '—'} ms`, icon: Zap },
    { label: 'Dead letters captured', value: snapshot?.deadLetters ?? '—', icon: ShieldCheck },
    {
      label: 'Database connections',
      value: snapshot
        ? `${snapshot.pool.total} total / ${snapshot.pool.idle} idle / ${snapshot.pool.waiting} waiting`
        : '—',
      icon: Database,
    },
    {
      label: 'Worker allocation',
      value: snapshot ? `${snapshot.activeWorkers} active / ${snapshot.concurrencyLimit} limit` : '—',
      icon: Terminal,
    },
  ];
  return (
    <div className="space-y-6 text-zinc-200 light:text-zinc-800">
      <div className="flex flex-wrap justify-between gap-3 items-center">
        <div>
          <h1 className="text-2xl font-semibold">Live text correlation</h1>
          <p className="text-sm text-zinc-500 mt-1">
            Native inventory · early intelligence · bounded stream processing
          </p>
        </div>
        <span
          className={`rounded-full px-3 py-2 text-xs font-mono ${snapshot?.health === 'HEALTHY' ? 'bg-emerald-500/15 text-emerald-500' : 'bg-amber-500/15 text-amber-500'}`}
          role="status"
        >
          {snapshot?.health || 'CONNECTING'}
        </span>
      </div>
      {snapshot && (
        <p className="text-xs font-mono text-zinc-500">
          Instance {snapshot.instanceId} · per-instance metrics
        </p>
      )}
      {error && (
        <p role="alert" className="rounded-xl border border-red-500/40 p-3 text-red-400">
          {error}
        </p>
      )}
      {snapshot && snapshot.droppedLogs > 0 && (
        <p role="alert" className="text-amber-400">
          {snapshot.droppedLogs} log events exceeded the bounded stdout queue. Check the log collector.
        </p>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {metrics.map((metric) => (
          <div
            key={metric.label}
            className="rounded-xl border border-zinc-800 light:border-zinc-200 bg-zinc-900/40 light:bg-white p-5"
          >
            <metric.icon className="h-4 w-4 text-cyan-500 mb-3" />
            <p className="text-xs text-zinc-500">{metric.label}</p>
            <p className="text-lg font-semibold mt-1">{metric.value}</p>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <section className="rounded-xl border border-zinc-800 light:border-zinc-200 p-5 space-y-4">
          <h2 className="font-semibold">Stream controls</h2>
          <div className="flex flex-wrap gap-3 items-end">
            <label className="text-sm">
              Concurrency (1–32)
              <input
                aria-label="Concurrency limit"
                className="block mt-2 bg-transparent border border-zinc-600 rounded-lg p-2 w-32"
                type="number"
                min={1}
                max={32}
                value={limit}
                onChange={(event) => setLimit(Number(event.target.value))}
              />
            </label>
            <button
              className="rounded-lg bg-cyan-700 text-white px-4 py-2 disabled:opacity-40"
              disabled={!canControl || busy || !Number.isInteger(limit) || limit < 1 || limit > 32}
              onClick={() => void mutate('concurrency', { limit })}
            >
              Apply limit
            </button>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              className="border border-amber-600 rounded-lg p-2 text-sm disabled:opacity-40"
              disabled={session?.role !== 'ADMIN' || busy}
              onClick={() => void mutate('fault', { fault: 'database' })}
            >
              Simulate DB disconnect
            </button>
            <button
              className="border border-amber-600 rounded-lg p-2 text-sm disabled:opacity-40"
              disabled={session?.role !== 'ADMIN' || busy}
              onClick={() => void mutate('fault', { fault: 'memory' })}
            >
              Simulate memory pressure
            </button>
          </div>
          <p className="text-xs text-zinc-500">
            Simulations last five seconds and are disabled in production. Controls and counters apply to this
            server instance.
          </p>
          <label className="block text-sm" htmlFor="advisory-ndjson">
            Advisory NDJSON (one JSON object per line)
          </label>
          <textarea
            id="advisory-ndjson"
            className="w-full min-h-44 bg-zinc-950 light:bg-zinc-50 rounded-lg p-3 font-mono text-xs border border-zinc-700"
            maxLength={524288}
            value={ndjson}
            onChange={(event) => setNdjson(event.target.value)}
            spellCheck={false}
          />
          <button
            className="rounded-lg bg-cyan-700 text-white px-4 py-2 disabled:opacity-40"
            disabled={!canControl || busy || !ndjson.trim()}
            onClick={() => void mutate('ingest', { ndjson })}
          >
            {busy ? 'Submitting…' : 'Queue advisory stream'}
          </button>
          {notice && (
            <p className="text-sm text-cyan-500" role="status">
              {notice}
            </p>
          )}
        </section>
        <section className="rounded-xl border border-zinc-800 light:border-zinc-200 p-5 min-w-0">
          <div className="flex justify-between items-center mb-4">
            <h2 className="font-semibold">Structured live logs</h2>
            <label className="text-xs">
              <input type="checkbox" checked={follow} onChange={(event) => setFollow(event.target.checked)} />{' '}
              Follow
            </label>
          </div>
          <pre
            ref={consoleRef}
            className="h-[440px] overflow-auto bg-zinc-950 rounded-lg p-3 text-[11px] leading-5"
            aria-label="Structured correlation logs"
          >
            {snapshot?.logs.map((log) => (
              <div
                key={log.sequence}
                className={
                  log.level === 'INFO'
                    ? 'text-cyan-300'
                    : log.level === 'WARN'
                      ? 'text-amber-300'
                      : 'text-red-400'
                }
              >
                {JSON.stringify(log)}
              </div>
            ))}
          </pre>
        </section>
      </div>
      <CorrelationOperations />
      <section className="rounded-xl border border-zinc-800 light:border-zinc-200 p-5">
        <div className="flex flex-wrap justify-between gap-3 mb-4">
          <h2 className="font-semibold">Confirmed identity and version matches</h2>
          <input
            aria-label="Filter correlation matches"
            className="bg-transparent rounded-lg border border-zinc-600 px-3 py-2 text-sm"
            placeholder="Filter vendor, product, confidence"
            maxLength={200}
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
        </div>
        <div className="overflow-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-zinc-500">
              <tr>
                {['Asset', 'Vendor / product', 'Confidence', 'Reason'].map((label) => (
                  <th key={label} className="p-3">
                    {label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {matches.map((match) => (
                <tr
                  key={`${match.advisoryId}:${match.assetId}`}
                  className="border-t border-zinc-800 light:border-zinc-200"
                >
                  <td className="p-3 font-mono text-xs">{match.assetId}</td>
                  <td className="p-3">
                    {match.vendor} / {match.product}
                  </td>
                  <td className="p-3">
                    <span
                      className={`rounded px-2 py-1 text-xs ${match.confidence === 'HIGH' ? 'bg-emerald-500/15 text-emerald-500' : 'bg-amber-500/15 text-amber-500'}`}
                    >
                      {match.confidence}
                    </span>
                  </td>
                  <td className="p-3">{match.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {matches.length === 0 && (
            <p className="text-sm text-zinc-500 p-6 text-center">
              No matches. Low-confidence evidence is stored separately for review.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
