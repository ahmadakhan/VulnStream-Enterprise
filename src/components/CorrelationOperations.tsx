import { useCallback, useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import type { CorrelationPolicy, CorrelationWorkflows } from '../../shared/correlation';
interface InventoryRow {
  id: string;
  vendor: string;
  product: string;
  version: string | null;
  recordId: string | null;
  assetTag: string | null;
}
const field = 'bg-transparent border border-zinc-600 rounded-lg p-2 text-sm';
const button = 'rounded-lg border border-cyan-700 px-3 py-2 text-sm disabled:opacity-40';
export function CorrelationOperations() {
  const { session, csrfToken } = useApp();
  const [state, setState] = useState<CorrelationWorkflows | null>(null);
  const [policy, setPolicy] = useState<CorrelationPolicy | null>(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState('');
  const [assetId, setAssetId] = useState('');
  const [note, setNote] = useState('');
  const [correction, setCorrection] = useState('');
  const [assets, setAssets] = useState<InventoryRow[]>([]);
  const [query, setQuery] = useState('');
  const [assetCursor, setAssetCursor] = useState<string | null>(null);
  const admin = session?.role === 'ADMIN';
  const operator = admin || session?.role === 'OPERATOR';
  const refresh = useCallback(async (signal?: AbortSignal) => {
    const response = await fetch('/api/correlation/workflows', { credentials: 'same-origin', signal });
    if (!response.ok) throw new Error(`Workflow unavailable (HTTP ${response.status})`);
    const data = (await response.json()) as CorrelationWorkflows;
    if (!signal?.aborted) {
      setState(data);
      setPolicy((current) => current || data.policy);
    }
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        await refresh(AbortSignal.any([controller.signal, AbortSignal.timeout(5000)]));
      } catch {
        if (!controller.signal.aborted) setNotice('Workflow data could not be refreshed');
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(() => void tick(), 5000);
      }
    };
    void tick();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [refresh]);
  const mutate = async (path: string, body: unknown, method = 'POST') => {
    if (busy) return;
    setBusy(true);
    setNotice('');
    try {
      const response = await fetch('/api/correlation/' + path, {
        method,
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) {
        const error = (await response.json()) as { error?: string };
        throw new Error(error.error || `Action failed (HTTP ${response.status})`);
      }
      const data = (await response.json()) as { removed?: number };
      setNotice(
        data.removed === undefined ? 'Decision saved' : `${data.removed} resolved or expired records removed`,
      );
      setSelected('');
      setNote('');
      setCorrection('');
      await refresh();
    } catch (reason) {
      setNotice(reason instanceof Error ? reason.message : 'Action failed');
    } finally {
      setBusy(false);
    }
  };
  const searchAssets = async (after?: string) => {
    setBusy(true);
    try {
      const params = new URLSearchParams({ q: query });
      if (after) params.set('after', after);
      const response = await fetch('/api/correlation/assets?' + params, {
        credentials: 'same-origin',
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error('Inventory search failed');
      const data = (await response.json()) as { assets: InventoryRow[]; nextCursor: string | null };
      setAssets(data.assets);
      setAssetCursor(data.nextCursor);
    } catch (reason) {
      setNotice(reason instanceof Error ? reason.message : 'Inventory search failed');
    } finally {
      setBusy(false);
    }
  };
  const replay = () => {
    let payload: unknown;
    if (correction.trim()) {
      try {
        payload = JSON.parse(correction);
      } catch {
        setNotice('Corrected advisory must be valid JSON');
        return;
      }
    }
    void mutate(`dead-letters/${selected}/decision`, {
      action: 'REPLAYED',
      note,
      ...(payload ? { payload } : {}),
    });
  };
  return (
    <section className="space-y-5 rounded-xl border border-zinc-800 light:border-zinc-200 p-5">
      <div>
        <h2 className="font-semibold">Review, delivery policy and retention</h2>
        <p className="text-xs text-zinc-500 mt-1">
          {state?.counts.pending ?? '—'} pending · {state?.counts.reviews ?? '—'} open reviews ·{' '}
          {state?.counts.deadLetters ?? '—'} unresolved dead letters
        </p>
      </div>
      {policy && (
        <form
          className="flex flex-wrap items-center gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            void mutate('policy', policy, 'PATCH');
          }}
        >
          <label className="text-sm flex gap-2 items-center">
            <input
              type="checkbox"
              disabled={!admin || busy}
              checked={policy.notificationsEnabled}
              onChange={(event) => setPolicy({ ...policy, notificationsEnabled: event.target.checked })}
            />
            Enable native notifications
          </label>
          <label className="text-sm flex gap-2 items-center">
            <input
              type="checkbox"
              disabled={!admin || busy}
              checked={policy.retentionEnabled}
              onChange={(event) => setPolicy({ ...policy, retentionEnabled: event.target.checked })}
            />
            Retain resolved data for
          </label>
          <label className="text-sm">
            <input
              aria-label="Correlation retention hours"
              className={field + ' w-24'}
              type="number"
              min={24}
              max={87600}
              disabled={!admin || busy}
              value={policy.retentionHours}
              onChange={(event) => setPolicy({ ...policy, retentionHours: Number(event.target.value) })}
            />{' '}
            hours
          </label>
          <button
            className={button}
            disabled={
              !admin ||
              busy ||
              !Number.isInteger(policy.retentionHours) ||
              policy.retentionHours < 24 ||
              policy.retentionHours > 87600
            }
          >
            Save policy
          </button>
          <button
            type="button"
            className={button}
            disabled={!admin || busy}
            onClick={() => void mutate('retention/run', {})}
          >
            Run retention batch
          </button>
        </form>
      )}
      <p className="text-xs text-zinc-500">
        Enabling notifications starts with new matches. HIGH evidence follows configured subscriptions; MEDIUM
        email requires approval in Email Queue. LOW evidence stays in review. Retention preserves open work
        and owner-managed tables.
      </p>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <div>
          <h3 className="font-medium mb-2">Low-confidence review</h3>
          <div className="max-h-64 overflow-auto space-y-2">
            {state?.reviews.map((review) => (
              <button
                key={review.id}
                disabled={!operator || busy}
                className={button + ' text-left w-full ' + (selected === review.id ? 'bg-cyan-900/30' : '')}
                onClick={() => {
                  setSelected(review.id);
                  setAssetId(review.assetId || '');
                  setNote('');
                  setCorrection('');
                }}
              >
                <span className="block">{review.title}</span>
                <span className="block text-xs text-zinc-500">{review.reason}</span>
              </button>
            ))}
            {state?.reviews.length === 0 && <p className="text-sm text-zinc-500">No open reviews.</p>}
          </div>
        </div>
        <div>
          <h3 className="font-medium mb-2">Encrypted dead letters</h3>
          <div className="max-h-64 overflow-auto space-y-2">
            {state?.deadLetters.map((letter) => (
              <button
                key={letter.id}
                disabled={!admin || busy}
                className={button + ' text-left w-full ' + (selected === letter.id ? 'bg-cyan-900/30' : '')}
                onClick={() => {
                  setSelected(letter.id);
                  setNote('');
                  setCorrection('');
                }}
              >
                <span className="block font-mono text-xs">{letter.id}</span>
                <span className="text-xs text-zinc-500">
                  {letter.errorCode} · {new Date(letter.createdAt).toLocaleString()}
                </span>
              </button>
            ))}
            {state?.deadLetters.length === 0 && (
              <p className="text-sm text-zinc-500">No unresolved dead letters.</p>
            )}
          </div>
        </div>
      </div>
      {selected && (
        <div className="border-t border-zinc-700 pt-4 space-y-3">
          <p className="text-xs font-mono break-all">Selected: {selected}</p>
          {state?.reviews
            .filter((review) => review.id === selected)
            .map((review) => (
              <details key={review.id} className="text-sm">
                <summary>Article context and source</summary>
                <p className="text-xs text-zinc-500 break-all mt-2">{review.url}</p>
                <p className="whitespace-pre-wrap mt-2">{review.content}</p>
              </details>
            ))}
          <label className="block text-sm">
            Decision note
            <input
              className={field + ' block w-full mt-1'}
              value={note}
              maxLength={1000}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Explain the decision (at least 5 characters)"
            />
          </label>
          {state?.reviews.some((review) => review.id === selected) ? (
            <>
              <label className="block text-sm">
                Target asset UUID
                <input
                  className={field + ' block w-full mt-1'}
                  value={assetId}
                  onChange={(event) => setAssetId(event.target.value)}
                  placeholder="Select a target using inventory search below"
                />
              </label>
              <button
                className={button}
                disabled={busy || note.trim().length < 5 || !assetId}
                onClick={() =>
                  void mutate(`reviews/${selected}/decision`, { decision: 'APPROVED', assetId, note })
                }
              >
                Approve applicability
              </button>{' '}
              <button
                className={button}
                disabled={busy || note.trim().length < 5}
                onClick={() => void mutate(`reviews/${selected}/decision`, { decision: 'DISMISSED', note })}
              >
                Dismiss review
              </button>
            </>
          ) : (
            <>
              <label className="block text-sm">
                Corrected advisory JSON (optional)
                <textarea
                  className={field + ' block w-full mt-1 min-h-24 font-mono'}
                  maxLength={262144}
                  value={correction}
                  onChange={(event) => setCorrection(event.target.value)}
                  placeholder="Leave empty to validate and replay the encrypted original"
                />
              </label>
              <button className={button} disabled={busy || note.trim().length < 5} onClick={replay}>
                Validate and replay
              </button>{' '}
              <button
                className={button}
                disabled={busy || note.trim().length < 5}
                onClick={() =>
                  void mutate(`dead-letters/${selected}/decision`, { action: 'DISMISSED', note })
                }
              >
                Dismiss dead letter
              </button>
            </>
          )}
        </div>
      )}
      <div className="border-t border-zinc-700 pt-4">
        <h3 className="font-medium mb-2">Connected native and monitored inventory</h3>
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            void searchAssets();
          }}
        >
          <input
            aria-label="Search connected inventory"
            className={field}
            maxLength={200}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Vendor or product"
          />
          <button className={button} disabled={busy}>
            Search inventory
          </button>
          {assetCursor && (
            <button
              type="button"
              className={button}
              disabled={busy}
              onClick={() => void searchAssets(assetCursor)}
            >
              Next page
            </button>
          )}
        </form>
        <div className="max-h-52 overflow-auto mt-3">
          {assets.map((asset) => (
            <button
              key={asset.id}
              className="block text-left text-xs border-t border-zinc-800 p-2 w-full"
              disabled={!operator}
              onClick={() => setAssetId(asset.id)}
            >
              <span className="font-medium">
                {asset.assetTag && `${asset.assetTag} · `}
                {asset.vendor} / {asset.product} {asset.version || 'version unspecified'}
              </span>
              <span className="block text-zinc-500 font-mono">
                {asset.id} · {asset.recordId ? 'Monitored Products' : 'Native inventory'}
              </span>
            </button>
          ))}
        </div>
      </div>
      {notice && (
        <p role="status" className="text-sm text-cyan-500">
          {notice}
        </p>
      )}
    </section>
  );
}
