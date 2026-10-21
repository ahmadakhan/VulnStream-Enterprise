import React, { useEffect, useState } from 'react';
import { Activity, AlertTriangle, CheckCircle2, Clock3, Cpu, Database, Mail, RefreshCw, Server, ShieldCheck } from 'lucide-react';
import { useApp } from '../context/AppContext';
import type { SystemHealth } from '../types';

type Tone = 'good' | 'warning' | 'neutral';
const tones: Record<Tone, string> = {
  good: 'bg-emerald-500/10 text-emerald-400 light:text-emerald-700 border-emerald-500/20',
  warning: 'bg-amber-500/10 text-amber-400 light:text-amber-700 border-amber-500/20',
  neutral: 'bg-zinc-500/10 text-zinc-400 light:text-zinc-600 border-zinc-500/20',
};
const panel = 'rounded-2xl border border-zinc-800/80 light:border-zinc-200 bg-zinc-900/50 light:bg-white shadow-sm';
const muted = 'text-zinc-400 light:text-zinc-600';
const date = (value: string | null) => value ? new Date(value).toLocaleString() : 'Not available';
const duration = (seconds: number) => {
  const days = Math.floor(seconds / 86400), hours = Math.floor(seconds % 86400 / 3600), minutes = Math.floor(seconds % 3600 / 60);
  return days ? `${days}d ${hours}h` : hours ? `${hours}h ${minutes}m` : minutes ? `${minutes}m` : `${seconds}s`;
};
function Badge({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: Tone }) {
  return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${tones[tone]}`}>
    <span className="h-1.5 w-1.5 rounded-full bg-current shrink-0" />{children}
  </span>;
}
export function SystemHealthView() {
  const { health } = useApp();
  const [status, setStatus] = useState<SystemHealth | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshFailed, setRefreshFailed] = useState(false);
  const refresh = async () => {
    setBusy(true);
    setRefreshFailed(false);
    try {
      const result = await health();
      if (result) setStatus(result);
      else setRefreshFailed(true);
    } catch {
      setRefreshFailed(true);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => { void refresh(); }, []);
  const count = (name: string) => status?.backlog.find(row => row.status === name)?.count ?? 0;
  const attention = status && (status.database !== 'connected' || ['STALE', 'NOT_OBSERVED'].includes(status.workerStatus) || !status.emailConfigured || !status.csrfEnforced || !status.ssrfEnforced || status.deliveryQueue.expiredLeases > 0 || count('FAILED') > 0);
  const workerTone: Tone = status?.workerStatus === 'HEALTHY' ? 'good' : status?.workerStatus === 'DISABLED' ? 'neutral' : 'warning';
  return (
    <div className="space-y-6 text-zinc-100 light:text-zinc-900" aria-busy={busy}>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold tracking-tight"><Activity className="h-5 w-5 text-zinc-400" />System Health</h1>
          <p className={`mt-1 text-xs ${muted}`}>Monitor infrastructure, background processing, and delivery readiness.</p>
        </div>
        <button className="inline-flex shrink-0 self-start items-center gap-2 rounded-xl border border-zinc-700 light:border-zinc-300 bg-zinc-900 light:bg-white px-3.5 py-2 text-xs font-medium transition hover:bg-zinc-800 light:hover:bg-zinc-100 disabled:opacity-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-400"
          disabled={busy} onClick={() => void refresh()}>
          <RefreshCw className={`h-3.5 w-3.5 ${busy ? 'animate-spin' : ''}`} />{busy ? 'Checking…' : 'Refresh status'}
        </button>
      </div>
      {refreshFailed && <div role="alert" className={`flex items-start gap-3 rounded-xl border p-4 text-sm ${tones.warning}`}>
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
        <span>Unable to refresh health data. {status ? 'The last successful snapshot is shown below.' : 'Try refreshing again.'}</span>
      </div>}
      {!status ? (
        busy ? <div role="status" className={`${panel} flex items-center justify-center gap-3 p-12 text-sm ${muted}`}><RefreshCw className="h-4 w-4 animate-spin" />Checking system components…</div>
          : <div className={`${panel} p-12 text-center text-sm ${muted}`}>Health data is not available. Refresh to try again.</div>
      ) : <>
        <div className={`${panel} flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between`}>
          <div className="flex items-center gap-3">
            <div className={`rounded-xl border p-2.5 ${refreshFailed || attention ? tones.warning : tones.good}`}>
              {refreshFailed || attention ? <AlertTriangle className="h-5 w-5" /> : <CheckCircle2 className="h-5 w-5" />}
            </div>
            <div><h2 className="text-sm font-semibold">{refreshFailed ? 'Health snapshot is out of date' : attention ? 'Attention needed' : status.workerStatus === 'DISABLED' ? 'Services reachable · worker disabled' : 'Monitored services are healthy'}</h2>
              <p className={`mt-1 text-xs ${muted}`}>{refreshFailed ? 'Refresh failed; values reflect the previous successful check.' : attention ? 'Review the highlighted components and delivery statuses below.' : 'Database connectivity and configured service checks passed.'}</p>
            </div>
          </div>
          <p className={`shrink-0 text-[11px] ${muted}`}>Last checked <time dateTime={status.checkedAt}>{date(status.checkedAt)}</time></p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[
            { name: 'Database', icon: Database, value: `${status.databaseLatencyMs} ms`, detail: 'Query response time', label: status.database === 'connected' ? 'Connected' : 'Unavailable', tone: status.database === 'connected' ? 'good' : 'warning' },
            { name: 'Background worker', icon: Server, value: status.workerStatus === 'DISABLED' ? 'Disabled' : status.heartbeatAgeSeconds === null ? 'Not observed' : `${status.heartbeatAgeSeconds}s ago`, detail: 'Latest worker heartbeat', label: status.workerStatus === 'HEALTHY' ? 'Healthy' : status.workerStatus === 'DISABLED' ? 'Disabled' : status.workerStatus === 'STALE' ? 'Stale heartbeat' : 'Waiting for heartbeat', tone: workerTone },
            { name: 'Email delivery', icon: Mail, value: status.emailProvider || 'SMTP', detail: 'Configured transport provider', label: status.emailConfigured ? 'Configured' : 'Setup required', tone: status.emailConfigured ? 'good' : 'warning' },
            { name: 'Process memory', icon: Cpu, value: `${Math.round(status.heapBytes / 1024 / 1024)} MiB`, detail: `Uptime ${duration(status.uptimeSeconds)}`, label: 'Heap in use', tone: 'neutral' },
          ].map(item => <div key={item.name} className={`${panel} p-5 min-w-0`}>
            <div className={`mb-4 flex items-center justify-between gap-2 text-xs ${muted}`}><h2>{item.name}</h2><item.icon className="h-4 w-4 shrink-0" /></div>
            <p className="break-words text-2xl font-semibold tracking-tight tabular-nums">{item.value}</p>
            <p className={`mt-1 mb-4 text-xs ${muted}`}>{item.detail}</p><Badge tone={item.tone as Tone}>{item.label}</Badge>
          </div>)}
        </div>
        <div className="grid gap-5 lg:grid-cols-3">
          <section className={`${panel} min-w-0 p-5 lg:col-span-2`} aria-labelledby="delivery-health-heading">
            <div className="flex flex-wrap items-center justify-between gap-2"><h2 id="delivery-health-heading" className="text-sm font-semibold">Delivery queue</h2><Badge tone={count('FAILED') ? 'warning' : 'neutral'}>{status.backlog.reduce((sum, row) => sum + row.count, 0)} total jobs</Badge></div>
            <p className={`mt-1 text-xs ${muted}`}>Transport acceptance is tracked separately from inbox delivery.</p>
            <div className="my-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[['QUEUED', 'Queued'], ['SENDING', 'Sending'], ['ACCEPTED', 'Accepted'], ['FAILED', 'Failed']].map(([key, label]) => <div key={key} className="rounded-xl border border-zinc-800/80 light:border-zinc-200 bg-zinc-950/40 light:bg-zinc-50 p-3">
                <p className={`text-[11px] ${key === 'FAILED' && count(key) ? 'text-amber-400 light:text-amber-700' : muted}`}>{label}</p>
                <p className="mt-2 text-xl font-semibold tabular-nums">{count(key).toLocaleString()}</p>
              </div>)}
            </div>
            <dl className="divide-y divide-zinc-800/70 light:divide-zinc-200 text-xs">
              {[
                ['Ready for processing', `${status.deliveryQueue.dueJobs} jobs`],
                ['Oldest due delivery', status.deliveryQueue.oldestDueCreatedAt ? date(status.deliveryQueue.oldestDueCreatedAt) : 'No deliveries due'],
                ['Next delayed retry', status.deliveryQueue.nextScheduledAttempt ? date(status.deliveryQueue.nextScheduledAttempt) : 'No retries scheduled'],
                ['Recoverable delivery leases', `${status.deliveryQueue.expiredLeases} expired`],
              ].map(([label, value]) => <div key={label} className="flex flex-col justify-between gap-1 py-3 sm:flex-row sm:gap-4"><dt className={muted}>{label}</dt><dd className="break-words tabular-nums sm:text-right">{value}</dd></div>)}
            </dl>
          </section>
          <section className={`${panel} min-w-0 p-5`} aria-labelledby="runtime-health-heading">
            <h2 id="runtime-health-heading" className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-zinc-400" />Runtime &amp; safeguards</h2>
            <div className="mt-5 space-y-4 text-xs">
              {[
                { label: 'HTTPS', value: status.httpsRequired ? 'Required' : 'Development mode', tone: status.httpsRequired ? 'good' : 'neutral' },
                { label: 'CSRF protection', value: status.csrfEnforced ? 'Enforced' : 'Not enforced', tone: status.csrfEnforced ? 'good' : 'warning' },
                { label: 'Outbound address validation', value: status.ssrfEnforced ? 'Enforced' : 'Not enforced', tone: status.ssrfEnforced ? 'good' : 'warning' },
              ].map(row => <div key={row.label} className="flex flex-wrap items-center justify-between gap-2"><span className={muted}>{row.label}</span><Badge tone={row.tone as Tone}>{row.value}</Badge></div>)}
              <div className="border-t border-zinc-800/70 light:border-zinc-200 pt-4"><p className={`flex items-center gap-1.5 ${muted}`}><Clock3 className="h-3.5 w-3.5" />Last scheduled run</p><p className="mt-2 break-words leading-relaxed">{status.lastScheduledRun ? date(status.lastScheduledRun) : 'Not yet run'}</p></div>
              <div><p className={muted}>Clock synchronization</p><p className="mt-2 leading-relaxed">{status.ntp}</p></div>
            </div>
          </section>
        </div>
      </>}
    </div>
  );
}
