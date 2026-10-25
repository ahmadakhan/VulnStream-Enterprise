import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Archive,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Database,
  HardDrive,
  Info,
  LockKeyhole,
  Newspaper,
  Play,
  RefreshCw,
  RotateCcw,
  Settings2,
  ShieldCheck,
  Webhook,
  X,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import type {
  AuditLog,
  RetentionConfig,
  RetentionKind,
  RetentionPreview,
  RetentionRunResult,
} from '../types';

const FALLBACK: RetentionConfig = {
  enabled: false,
  retentionHours: 24,
  cleanupIntervalMinutes: 60,
  maxArchivedRecords: 10000,
  autoCleanup: true,
  retentionMode: 'rolling',
};

const MODES = [
  {
    id: 'strict',
    label: 'Strict',
    description: 'Delete every record whose timestamp is older than the window.',
  },
  {
    id: 'rolling',
    label: 'Rolling',
    description: 'Delete expired records, then trim the oldest until the archive ceiling is met.',
  },
  {
    id: 'checkpoints',
    label: 'Checkpoints',
    description: 'Delete expired records but keep the newest record from each UTC day.',
  },
] as const;

const panel =
  'rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white';
const muted = 'text-zinc-400 light:text-zinc-600';
const badge = 'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium';

const stamp = (value: string | null | undefined) => {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? '—'
    : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
};

const hours = (value: number) => {
  if (value >= 24 && value % 24 === 0) {
    const days = value / 24;
    return `${days} day${days === 1 ? '' : 's'}`;
  }
  return `${value} hour${value === 1 ? '' : 's'}`;
};

const toConfig = (value?: Partial<RetentionConfig> | null): RetentionConfig => ({
  enabled: value?.enabled ?? FALLBACK.enabled,
  retentionHours: value?.retentionHours ?? FALLBACK.retentionHours,
  cleanupIntervalMinutes: value?.cleanupIntervalMinutes ?? FALLBACK.cleanupIntervalMinutes,
  maxArchivedRecords: value?.maxArchivedRecords ?? FALLBACK.maxArchivedRecords,
  autoCleanup: value?.autoCleanup ?? FALLBACK.autoCleanup,
  retentionMode: value?.retentionMode ?? FALLBACK.retentionMode,
});

function SectionHeading({
  icon: Icon,
  title,
  description,
  id,
}: {
  icon: typeof Settings2;
  title: string;
  description: string;
  id?: string;
}) {
  return (
    <div className="flex items-start gap-3.5">
      <span className="ui-section-icon">
        <Icon className="h-4 w-4" aria-hidden="true" />
      </span>
      <div>
        <h2 id={id} className="ui-card-title">
          {title}
        </h2>
        <p className="ui-description mt-1">{description}</p>
      </div>
    </div>
  );
}

interface FootprintRow {
  label: string;
  tab: string;
  icon: typeof Database;
  total: number;
  /** Present only for kinds the retention policy may delete. */
  past?: number;
}

function RecordRow({ row, onOpen }: { row: FootprintRow; onOpen: (tab: string) => void }) {
  return (
    <li>
      <button
        type="button"
        onClick={() => onOpen(row.tab)}
        className="group flex w-full items-center gap-3 py-2.5 text-left text-xs transition"
      >
        <row.icon className={`h-3.5 w-3.5 shrink-0 ${muted}`} aria-hidden="true" />
        <span className="flex-1 font-medium text-zinc-300 light:text-zinc-700">{row.label}</span>
        {row.past === undefined ? (
          <LockKeyhole className="h-3 w-3 shrink-0 text-zinc-600" aria-label="Never removed by retention" />
        ) : (
          row.past > 0 && (
            <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium tabular-nums text-amber-400 light:text-amber-700">
              {row.past.toLocaleString()} past
            </span>
          )
        )}
        <span className="tabular-nums text-zinc-200 light:text-zinc-800">{row.total.toLocaleString()}</span>
        <ChevronRight
          className={`h-3.5 w-3.5 shrink-0 text-zinc-600 transition group-hover:translate-x-0.5 ${muted}`}
          aria-hidden="true"
        />
      </button>
    </li>
  );
}

export const ArchiveRetentionView: React.FC = () => {
  const {
    settings,
    updateSettings,
    session,
    counts,
    setActiveTab,
    runRetentionCleanup,
    previewRetention,
    fetchCollection,
    refreshVersion,
  } = useApp();
  const admin = session?.role === 'ADMIN';

  const saved = useMemo(() => toConfig(settings?.retentionConfig), [settings?.retentionConfig]);
  const [form, setForm] = useState<RetentionConfig>(saved);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const [running, setRunning] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [runNotice, setRunNotice] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  // Exact footprint counts come from the server. The snapshot only carries
  // capped recent slices, so computing totals from it would under-report.
  const [preview, setPreview] = useState<RetentionPreview | null>(null);
  const [previewVersion, setPreviewVersion] = useState(0);
  const dirty = JSON.stringify(form) !== JSON.stringify(saved);

  useEffect(() => {
    if (!dirty) setForm(saved);
    // Only re-sync when the persisted policy changes; an in-progress edit must survive it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(saved)]);

  // A policy edit or disabling the policy invalidates an armed manual cleanup.
  useEffect(() => {
    if (dirty || !form.enabled) setConfirming(false);
  }, [dirty, form.enabled]);

  // Refresh the server-side footprint as the operator edits the policy. The
  // context callback is intentionally omitted from the dependency list: the
  // provider recreates it on every clock tick, which would otherwise refetch
  // this preview once per second.
  useEffect(() => {
    if (!admin) return;
    let active = true;
    const timer = setTimeout(() => {
      void previewRetention({
        enabled: form.enabled,
        retentionHours: form.retentionHours,
        maxArchivedRecords: form.maxArchivedRecords,
        retentionMode: form.retentionMode,
      }).then((value) => {
        if (active && value) setPreview(value);
      });
    }, 200);
    return () => {
      active = false;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [admin, form.enabled, form.retentionHours, form.maxArchivedRecords, form.retentionMode, previewVersion]);

  const patch = (update: Partial<RetentionConfig>) => {
    setForm((current) => ({ ...current, ...update }));
    setNotice(null);
  };

  const numberChange =
    (key: 'retentionHours' | 'cleanupIntervalMinutes' | 'maxArchivedRecords', min: number, max: number) =>
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const value = Number(event.target.value);
      patch({ [key]: Number.isFinite(value) ? Math.min(max, Math.max(min, Math.trunc(value))) : min });
    };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!admin || saving || !dirty) return;
    setSaving(true);
    setNotice(null);
    try {
      const ok = await updateSettings({ retentionConfig: form });
      setNotice(
        ok
          ? { tone: 'success', text: 'Retention policy saved.' }
          : { tone: 'error', text: 'Retention policy was not saved. See the error banner for details.' },
      );
    } finally {
      setSaving(false);
    }
  };

  // The snapshot's audit slice is capped, so look up the latest cleanup through
  // the paginated audit endpoint instead of scanning recent entries only.
  const [lastCleanup, setLastCleanup] = useState<AuditLog | null>(null);
  useEffect(() => {
    if (!admin) return;
    let active = true;
    void fetchCollection<AuditLog>('auditLogs', {
      page: 1,
      pageSize: 20,
      search: 'Retention cleanup',
    })
      .then((page) => {
        if (active)
          setLastCleanup(page.items.find((entry) => entry.event === 'Retention cleanup') ?? null);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [admin, refreshVersion]);

  const cutoff =
    preview?.cutoff ?? new Date(Date.now() - form.retentionHours * 3_600_000).toISOString();
  const footprint = (kind: RetentionKind): { total: number; past: number } =>
    preview?.records[kind] ?? { total: counts[kind], past: 0 };

  // Only these kinds are eligible for deletion; each timestamp matches the
  // field the corresponding table shows to operators.
  const removable: FootprintRow[] = [
    {
      label: 'Threat cache',
      tab: 'threat-data',
      icon: Database,
      total: footprint('cveData').total,
      past: footprint('cveData').past,
    },
    {
      label: 'News cache',
      tab: 'threat-data',
      icon: Newspaper,
      total: footprint('intelligenceArticles').total,
      past: footprint('intelligenceArticles').past,
    },
    {
      label: 'Delivery log',
      tab: 'emails',
      icon: Clock3,
      total: footprint('emailLogs').total,
      past: footprint('emailLogs').past,
    },
    {
      label: 'Webhook log',
      tab: 'recipients',
      icon: Webhook,
      total: footprint('webhookLogs').total,
      past: footprint('webhookLogs').past,
    },
    {
      label: 'Executions',
      tab: 'pipeline',
      icon: Settings2,
      total: footprint('executions').total,
      past: footprint('executions').past,
    },
  ];
  const retained: FootprintRow[] = [
    {
      label: 'Findings',
      tab: 'findings',
      icon: ShieldCheck,
      total: preview?.protected.findings ?? counts.findings,
    },
    {
      label: 'Advisories',
      tab: 'advisories',
      icon: Archive,
      total: preview?.protected.advisories ?? counts.advisories,
    },
    {
      label: 'Audit history',
      tab: 'logs',
      icon: HardDrive,
      total: preview?.protected.auditLogs ?? counts.auditLogs,
    },
  ];
  const totalRecords = [...removable, ...retained].reduce((sum, row) => sum + row.total, 0);
  const removableRecords = removable.reduce((sum, row) => sum + row.total, 0);
  const expiredRecords = removable.reduce((sum, row) => sum + (row.past ?? 0), 0);
  const mode = MODES.find((item) => item.id === form.retentionMode) ?? MODES[1];

  const runCleanup = async () => {
    if (!admin || running || !form.enabled || dirty) return;
    // First click arms a destructive action; the second click performs it.
    if (!confirming) {
      setConfirming(true);
      setRunNotice(null);
      return;
    }
    setConfirming(false);
    setRunning(true);
    setRunNotice(null);
    try {
      const result = await runRetentionCleanup();
      setRunNotice(
        result
          ? {
              tone: 'success',
              text: result.deleted
                ? `Removed ${result.deleted.toLocaleString()} record${result.deleted === 1 ? '' : 's'} using ${result.mode} mode.`
                : 'Cleanup completed. Nothing was outside the policy.',
            }
          : { tone: 'error', text: 'Cleanup did not run. See the error banner for the reason.' },
      );
    } finally {
      setRunning(false);
      // Cleanup removed rows; refresh the exact server footprint.
      setPreviewVersion((value) => value + 1);
    }
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6 text-zinc-100 light:text-zinc-900">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
            Archive &amp; retention
          </p>
          <h1 className="mt-1 flex items-center gap-2.5 text-2xl font-semibold tracking-tight">
            <span className="grid h-9 w-9 place-items-center rounded-xl border border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700">
              <Archive className="h-4 w-4" aria-hidden="true" />
            </span>
            Archives &amp; retention
          </h1>
          <p className={`mt-2 max-w-2xl text-sm ${muted}`}>
            Set how long correlated records stay available and review what currently sits outside that window.
          </p>
        </div>
        <span
          className={`${badge} shrink-0 self-start sm:self-auto ${
            form.enabled
              ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400 light:text-emerald-700'
              : 'border-zinc-500/20 bg-zinc-500/10 text-zinc-400 light:text-zinc-600'
          }`}
        >
          <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-current" />
          {form.enabled ? 'Policy enabled' : 'Policy disabled'}
        </span>
      </header>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <form className="ui-card space-y-6" aria-labelledby="retention-policy-title" onSubmit={submit}>
          <SectionHeading
            icon={ShieldCheck}
            id="retention-policy-title"
            title="Retention policy"
            description="Stored with workspace settings so operators share one documented window and mode."
          />

          <div className="grid gap-3 sm:grid-cols-2">
            <label className="ui-check-row cursor-pointer text-xs leading-relaxed">
              <input
                type="checkbox"
                checked={form.enabled}
                disabled={!admin}
                onChange={(event) => patch({ enabled: event.target.checked })}
              />
              <span>
                <span className="block font-medium text-zinc-200 light:text-zinc-800">Enforce retention</span>
                <span className="ui-description mt-0.5 block">
                  Treat the window below as the active data-retention policy.
                </span>
              </span>
            </label>
            <label className="ui-check-row cursor-pointer text-xs leading-relaxed">
              <input
                type="checkbox"
                checked={form.autoCleanup}
                disabled={!admin || !form.enabled}
                onChange={(event) => patch({ autoCleanup: event.target.checked })}
              />
              <span>
                <span className="block font-medium text-zinc-200 light:text-zinc-800">Automatic cleanup</span>
                <span className="ui-description mt-0.5 block">
                  Run the policy on a schedule instead of waiting for a manual review.
                </span>
              </span>
            </label>
          </div>

          <div className="grid gap-x-5 gap-y-4 sm:grid-cols-2">
            <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
              Retention window
              <span className="ml-1 font-normal text-zinc-500">(hours)</span>
              <input
                type="number"
                min={1}
                max={8760}
                required
                inputMode="numeric"
                disabled={!admin}
                className="ui-field"
                value={form.retentionHours}
                onChange={numberChange('retentionHours', 1, 8760)}
              />
              <span className="ui-description mt-1.5 block">
                {hours(form.retentionHours)} — anything older is outside the policy.
              </span>
            </label>
            <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
              Archive ceiling
              <span className="ml-1 font-normal text-zinc-500">(records)</span>
              <input
                type="number"
                min={1000}
                max={1000000}
                required
                inputMode="numeric"
                disabled={!admin}
                className="ui-field"
                value={form.maxArchivedRecords}
                onChange={numberChange('maxArchivedRecords', 1000, 1000000)}
              />
              <span className="ui-description mt-1.5 block">
                Upper bound used by rolling mode before the oldest records are dropped.
              </span>
            </label>
            <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700 sm:col-span-2">
              Cleanup interval
              <span className="ml-1 font-normal text-zinc-500">(minutes)</span>
              <input
                type="number"
                min={1}
                max={1440}
                required
                inputMode="numeric"
                disabled={!admin || !form.enabled || !form.autoCleanup}
                className="ui-field"
                value={form.cleanupIntervalMinutes}
                onChange={numberChange('cleanupIntervalMinutes', 1, 1440)}
              />
              <span className="ui-description mt-1.5 block">
                {form.enabled && form.autoCleanup
                  ? `A cleanup pass would run every ${form.cleanupIntervalMinutes} minute${
                      form.cleanupIntervalMinutes === 1 ? '' : 's'
                    }.`
                  : 'Enable automatic cleanup to schedule passes.'}
              </span>
            </label>
          </div>

          <fieldset className="space-y-3">
            <legend className="text-xs font-medium text-zinc-300 light:text-zinc-700">Retention mode</legend>
            <div className="grid gap-2.5 sm:grid-cols-3">
              {MODES.map((item) => {
                const selected = form.retentionMode === item.id;
                return (
                  <label
                    key={item.id}
                    className={`flex cursor-pointer items-start gap-2.5 rounded-xl border p-3 text-xs leading-relaxed transition ${
                      selected
                        ? 'border-blue-500/50 bg-blue-500/5 light:border-blue-400 light:bg-blue-50'
                        : 'border-zinc-800/80 bg-zinc-950/30 hover:border-zinc-700 light:border-zinc-200 light:bg-zinc-50 light:hover:border-zinc-300'
                    }`}
                  >
                    <input
                      type="radio"
                      name="retention-mode"
                      value={item.id}
                      checked={selected}
                      disabled={!admin}
                      onChange={() => patch({ retentionMode: item.id })}
                      className="mt-0.5"
                    />
                    <span>
                      <span className="block font-semibold text-zinc-200 light:text-zinc-800">{item.label}</span>
                      <span className="ui-description mt-0.5 block">{item.description}</span>
                    </span>
                  </label>
                );
              })}
            </div>
          </fieldset>

          <div className="ui-actions justify-between">
            <div aria-live="polite" className="min-h-5">
              {notice ? (
                <p
                  role={notice.tone === 'error' ? 'alert' : undefined}
                  className={`inline-flex items-center gap-2 text-xs font-medium ${
                    notice.tone === 'success'
                      ? 'text-emerald-400 light:text-emerald-700'
                      : 'text-rose-400 light:text-rose-700'
                  }`}
                >
                  {notice.tone === 'success' ? (
                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  {notice.text}
                </p>
              ) : (
                <span className={`text-xs ${muted}`}>
                  {!admin
                    ? 'Administrator role required to change the retention policy.'
                    : dirty
                      ? 'Unsaved policy changes.'
                      : 'Policy matches the saved workspace settings.'}
                </span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                className="ui-secondary"
                disabled={!admin || saving || !dirty}
                onClick={() => {
                  setForm(saved);
                  setNotice(null);
                }}
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                Reset
              </button>
              <button type="submit" className="ui-primary" disabled={!admin || saving || !dirty}>
                {saving ? (
                  'Saving…'
                ) : (
                  <>
                    <Check className="h-3.5 w-3.5" aria-hidden="true" />
                    Save policy
                  </>
                )}
              </button>
            </div>
          </div>
        </form>

        <div className="space-y-6">
          <section className={`${panel} p-5`} aria-labelledby="policy-summary-title">
            <div className="flex items-center justify-between gap-3">
              <h2 id="policy-summary-title" className="ui-card-title">
                Policy summary
              </h2>
              <Info className="h-4 w-4 text-zinc-500" aria-hidden="true" />
            </div>
            <dl className="mt-4 space-y-3 text-xs">
              <div className="flex items-baseline justify-between gap-3">
                <dt className={muted}>Window</dt>
                <dd className="font-medium tabular-nums">{hours(form.retentionHours)}</dd>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <dt className={muted}>Cutoff</dt>
                <dd className="text-right font-medium tabular-nums">{stamp(new Date(cutoff).toISOString())}</dd>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <dt className={muted}>Mode</dt>
                <dd className="font-medium">{mode.label}</dd>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <dt className={muted}>Schedule</dt>
                <dd className="font-medium">
                  {form.enabled && form.autoCleanup
                    ? `Every ${form.cleanupIntervalMinutes} min`
                    : 'Paused'}
                </dd>
              </div>
              <div className="flex items-baseline justify-between gap-3 border-t border-zinc-800/70 pt-3 light:border-zinc-200">
                <dt className={muted}>Eligible records</dt>
                <dd className="font-medium tabular-nums">{removableRecords.toLocaleString()}</dd>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <dt className={muted}>Past window</dt>
                <dd
                  className={`font-medium tabular-nums ${
                    expiredRecords > 0 ? 'text-amber-400 light:text-amber-700' : 'text-emerald-400 light:text-emerald-700'
                  }`}
                >
                  {expiredRecords.toLocaleString()} record{expiredRecords === 1 ? '' : 's'}
                </dd>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <dt className={muted}>Last removal</dt>
                <dd className="text-right font-medium tabular-nums">{stamp(lastCleanup?.timestamp)}</dd>
              </div>
            </dl>
          </section>

          <section className={`${panel} p-5`} aria-labelledby="stored-records-title">
            <div className="flex items-baseline justify-between gap-3">
              <h2 id="stored-records-title" className="ui-card-title">
                Stored records
              </h2>
              <span className={`text-[11px] tabular-nums ${muted}`}>{totalRecords.toLocaleString()} total</span>
            </div>
            <h3 className="mt-4 text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
              Removable by policy
            </h3>
            <ul className="mt-1 divide-y divide-zinc-800/70 light:divide-zinc-200">
              {removable.map((row) => (
                <RecordRow key={row.label} row={row} onOpen={setActiveTab} />
              ))}
            </ul>
            <h3 className="mt-4 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
              <LockKeyhole className="h-3 w-3" aria-hidden="true" />
              Always retained
            </h3>
            <ul className="mt-1 divide-y divide-zinc-800/70 light:divide-zinc-200">
              {retained.map((row) => (
                <RecordRow key={row.label} row={row} onOpen={setActiveTab} />
              ))}
            </ul>
          </section>
        </div>
      </div>

      <section className={`${panel} p-5`} aria-labelledby="maintenance-title">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-3.5">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 light:text-emerald-700">
              <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <h2 id="maintenance-title" className="ui-card-title">
                How cleanup works
              </h2>
              <p className={`mt-1 max-w-2xl text-xs leading-relaxed ${muted}`}>
                Saving the policy makes it live. When automatic cleanup is on, the worker applies it every{' '}
                {form.cleanupIntervalMinutes} minute{form.cleanupIntervalMinutes === 1 ? '' : 's'}. You can also
                run a pass immediately; deletion always uses the saved policy, so save pending edits first.
              </p>
            </div>
          </div>
          <div className="flex shrink-0 flex-col items-stretch gap-2 sm:items-end">
            <div className="flex flex-wrap gap-2">
              {confirming && (
                <button
                  type="button"
                  className="ui-secondary"
                  disabled={running}
                  onClick={() => setConfirming(false)}
                >
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                  Cancel
                </button>
              )}
              <button
                type="button"
                className={
                  confirming
                    ? 'inline-flex items-center justify-center gap-2 rounded-xl bg-red-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-60'
                    : 'ui-primary'
                }
                disabled={!admin || running || !form.enabled || dirty}
                onClick={runCleanup}
              >
                {running ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                ) : confirming ? (
                  <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
                ) : (
                  <Play className="h-3.5 w-3.5" aria-hidden="true" />
                )}
                {running ? 'Running…' : confirming ? 'Confirm cleanup' : 'Run cleanup now'}
              </button>
            </div>
            <span aria-live="polite" className={`text-right text-[11px] ${muted}`}>
              {!admin
                ? 'Administrator role required.'
                : !form.enabled
                  ? 'Enable the policy to run cleanup.'
                  : dirty
                    ? 'Save the policy before running cleanup.'
                    : confirming
                      ? form.retentionMode === 'strict'
                        ? `${expiredRecords.toLocaleString()} record${expiredRecords === 1 ? '' : 's'} past the window will be removed.`
                        : `Applies ${mode.label.toLowerCase()} mode to ${expiredRecords.toLocaleString()} record${expiredRecords === 1 ? '' : 's'} past the window.`
                      : 'Applies the saved policy immediately.'}
            </span>
          </div>
        </div>

        {runNotice && (
          <p
            role={runNotice.tone === 'error' ? 'alert' : 'status'}
            className={`mt-4 inline-flex items-center gap-2 text-xs font-medium ${
              runNotice.tone === 'success'
                ? 'text-emerald-400 light:text-emerald-700'
                : 'text-rose-400 light:text-rose-700'
            }`}
          >
            {runNotice.tone === 'success' ? (
              <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
            ) : (
              <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            {runNotice.text}
          </p>
        )}

        <div className={`mt-5 grid gap-5 border-t border-zinc-800/70 pt-4 text-xs light:border-zinc-200 sm:grid-cols-2`}>
          <div>
            <h3 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
              Removed when past the window
            </h3>
            <ul className={`mt-2 space-y-1.5 ${muted}`}>
              <li>Threat cache</li>
              <li>News cache</li>
              <li>Delivery log</li>
              <li>Webhook log</li>
              <li>Pipeline executions</li>
            </ul>
          </div>
          <div>
            <h3 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
              Never removed by this policy
            </h3>
            <ul className={`mt-2 space-y-1.5 ${muted}`}>
              <li>Findings and advisories</li>
              <li>Audit history</li>
              <li>Feed checkpoints and source snapshots</li>
              <li>Monitored products, recipients and settings</li>
            </ul>
          </div>
        </div>

        <p className={`mt-4 text-[11px] leading-relaxed ${muted}`}>
          The separate housekeeping loop still expires sessions, clears old login attempts, prunes settled outbox
          jobs after 30 days and operational events after 90 days. That housekeeping is fixed and independent of
          this policy.
        </p>
      </section>
    </div>
  );
};
