import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Clock3, Inbox, RefreshCw, RotateCw, Search, Trash2 } from 'lucide-react';
import { useApp } from '../context/AppContext';
import type { EmailQueueItem } from '../types';

const panel =
  'rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white';
const date = (value: string) => {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? 'Not scheduled'
    : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(parsed);
};

export function EmailQueueView() {
  const { listEmailQueue, retryEmailDelivery, deleteEmailQueueItem, session } = useApp();
  const [items, setItems] = useState<EmailQueueItem[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [retryingId, setRetryingId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<EmailQueueItem | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const canManage = session?.role === 'ADMIN' || session?.role === 'OPERATOR';

  const refresh = async () => {
    setLoading(true);
    const result = await listEmailQueue();
    if (result) {
      setItems(result);
      setLoadError(false);
    } else {
      setLoadError(true);
    }
    setLoading(false);
  };

  useEffect(() => {
    void refresh();
  }, []);

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return items;
    return items.filter((item) =>
      [item.recipientEmail, item.subject, item.advisoryId, item.status, item.error || '']
        .join(' ')
        .toLowerCase()
        .includes(term),
    );
  }, [items, search]);
  const queued = items.filter((item) => item.status === 'QUEUED').length;
  const sending = items.filter((item) => item.status === 'SENDING').length;
  const failed = items.filter((item) => item.status === 'FAILED').length;

  const retry = async (id: string) => {
    setRetryingId(id);
    const result = await retryEmailDelivery(id);
    if (result) await refresh();
    setRetryingId(null);
  };

  const confirmDelete = async () => {
    if (!deleting || deleteBusy) return;
    setDeleteBusy(true);
    const result = await deleteEmailQueueItem(deleting.id);
    if (result) {
      setItems((current) => current.filter((item) => item.id !== deleting.id));
      setDeleting(null);
    }
    setDeleteBusy(false);
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
            Autonomous pipeline
          </p>
          <h1 className="mt-1 flex items-center gap-2.5 text-2xl font-semibold tracking-tight">
            <span className="grid h-9 w-9 place-items-center rounded-xl border border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700">
              <Inbox className="h-4 w-4" aria-hidden="true" />
            </span>
            Email queue
          </h1>
          <p className="ui-description mt-2 max-w-2xl text-sm">
            Track pending and failed email deliveries. Retry failed jobs or remove queued and failed jobs that
            should not be sent.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void refresh()}
          disabled={loading}
          className="ui-secondary self-start sm:self-auto"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
          {loading ? 'Refreshing…' : 'Refresh queue'}
        </button>
      </header>

      <section className="grid gap-3 sm:grid-cols-3" aria-label="Email queue totals">
        {[
          { label: 'Queued', count: queued, tone: 'text-blue-300 light:text-blue-700' },
          { label: 'Sending', count: sending, tone: 'text-amber-300 light:text-amber-700' },
          { label: 'Failed', count: failed, tone: 'text-rose-300 light:text-rose-700' },
        ].map((entry) => (
          <div key={entry.label} className={`${panel} flex items-center justify-between p-4`}>
            <span className="text-xs text-zinc-400 light:text-zinc-600">{entry.label}</span>
            <span className={`text-xl font-semibold tabular-nums ${entry.tone}`}>{entry.count}</span>
          </div>
        ))}
      </section>

      <section className={`${panel} overflow-hidden`} aria-label="Email queue jobs">
        <div className="flex flex-col gap-3 border-b border-zinc-800/80 p-4 sm:flex-row sm:items-center sm:justify-between light:border-zinc-200">
          <div className="relative w-full sm:max-w-sm">
            <Search className="absolute left-3 top-3 h-4 w-4 text-zinc-500" aria-hidden="true" />
            <input
              type="search"
              aria-label="Search email queue"
              placeholder="Search recipient, subject, or advisory…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              className="w-full pl-9"
            />
          </div>
          <p className="text-xs text-zinc-500">
            {filtered.length} {filtered.length === 1 ? 'job' : 'jobs'}
            {!canManage && <span> · Read only</span>}
          </p>
        </div>

        {loadError ? (
          <div role="alert" className="flex flex-col items-center gap-3 px-6 py-12 text-center">
            <AlertTriangle className="h-5 w-5 text-amber-400" aria-hidden="true" />
            <p className="text-sm font-medium">Queue could not be loaded</p>
            <p className="text-xs text-zinc-500">Check the connection and try again.</p>
            <button type="button" className="ui-secondary" onClick={() => void refresh()}>
              Try again
            </button>
          </div>
        ) : loading && !items.length ? (
          <div
            role="status"
            className="flex items-center justify-center gap-2 px-6 py-12 text-sm text-zinc-500"
          >
            <RefreshCw className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading email queue…
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center gap-2 px-6 py-12 text-center">
            <Inbox className="h-6 w-6 text-zinc-500" aria-hidden="true" />
            <p className="text-sm font-medium">
              {search ? 'No matching email jobs' : 'The email queue is clear'}
            </p>
            <p className="text-xs text-zinc-500">
              {search
                ? 'Try a different search term.'
                : 'Pending and failed email deliveries will appear here.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-xs">
              <thead className="border-b border-zinc-800/80 bg-zinc-950/50 text-[10px] uppercase tracking-wider text-zinc-500 light:border-zinc-200 light:bg-zinc-50">
                <tr>
                  <th scope="col" className="px-4 py-3">
                    Recipient / subject
                  </th>
                  <th scope="col" className="px-4 py-3">
                    Advisory
                  </th>
                  <th scope="col" className="px-4 py-3">
                    Status
                  </th>
                  <th scope="col" className="px-4 py-3">
                    Attempts / next attempt
                  </th>
                  <th scope="col" className="px-4 py-3">
                    Last error
                  </th>
                  <th scope="col" className="px-4 py-3 text-right">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 light:divide-zinc-200">
                {filtered.map((item) => (
                  <tr key={item.id} className="align-top hover:bg-zinc-800/20 light:hover:bg-zinc-50">
                    <td className="max-w-sm px-4 py-3">
                      <p
                        className="truncate font-medium text-zinc-200 light:text-zinc-800"
                        title={item.recipientEmail}
                      >
                        {item.recipientEmail || 'Recipient unavailable'}
                      </p>
                      <p className="mt-1 line-clamp-2 text-zinc-500" title={item.subject}>
                        {item.subject}
                      </p>
                    </td>
                    <td className="px-4 py-3 font-mono text-zinc-400">{item.advisoryId}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-medium ${
                          item.status === 'FAILED'
                            ? 'border-rose-500/20 bg-rose-500/10 text-rose-300 light:text-rose-700'
                            : item.status === 'SENDING'
                              ? 'border-amber-500/20 bg-amber-500/10 text-amber-300 light:text-amber-700'
                              : 'border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700'
                        }`}
                      >
                        {item.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-zinc-400">
                      <span className="block tabular-nums">
                        {item.attempts} {item.attempts === 1 ? 'attempt' : 'attempts'}
                      </span>
                      <span className="mt-1 block text-[10px] text-zinc-500">{date(item.nextAttemptAt)}</span>
                    </td>
                    <td className="max-w-xs px-4 py-3 text-zinc-500">
                      {item.error ? (
                        <span className="line-clamp-2" title={item.error}>
                          {item.error}
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {canManage && (
                        <div className="inline-flex items-center justify-end gap-2">
                          {item.status === 'FAILED' && (
                            <button
                              type="button"
                              onClick={() => void retry(item.id)}
                              disabled={retryingId === item.id}
                              className="ui-secondary min-h-8 px-2.5 py-1 text-[11px]"
                            >
                              <RotateCw
                                className={`h-3 w-3 ${retryingId === item.id ? 'animate-spin' : ''}`}
                                aria-hidden="true"
                              />
                              Retry
                            </button>
                          )}
                          {item.status !== 'SENDING' && (
                            <button
                              type="button"
                              onClick={() => setDeleting(item)}
                              className="inline-flex min-h-8 items-center gap-1.5 rounded-lg border border-rose-500/20 px-2.5 py-1 text-[11px] font-medium text-rose-300 transition hover:bg-rose-500/10 light:text-rose-700"
                              aria-label={`Delete queued email to ${item.recipientEmail}`}
                            >
                              <Trash2 className="h-3 w-3" aria-hidden="true" /> Delete
                            </button>
                          )}
                          {item.status === 'SENDING' && (
                            <span className="inline-flex items-center gap-1.5 text-[10px] text-zinc-500">
                              <Clock3 className="h-3 w-3" aria-hidden="true" /> In progress
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {deleting && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !deleteBusy) setDeleting(null);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-email-title"
            className={`${panel} w-full max-w-md p-5`}
          >
            <h2 id="delete-email-title" className="text-sm font-semibold">
              Delete queued email?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              This removes the delivery job for{' '}
              <span className="font-medium text-zinc-200 light:text-zinc-800">{deleting.recipientEmail}</span>{' '}
              from the queue and marks it cancelled in the delivery history.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                className="ui-secondary"
                disabled={deleteBusy}
                onClick={() => setDeleting(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 text-xs font-semibold text-rose-300 hover:bg-rose-500/20 light:text-rose-700"
                disabled={deleteBusy}
                onClick={() => void confirmDelete()}
              >
                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                {deleteBusy ? 'Deleting…' : 'Delete job'}
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
