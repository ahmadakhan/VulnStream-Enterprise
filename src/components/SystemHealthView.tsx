import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
export function SystemHealthView() {
  const { health } = useApp(),
    [status, setStatus] = useState<any>(null),
    [busy, setBusy] = useState(false);
  const refresh = async () => {
    setBusy(true);
    try {
      const result = await health();
      if (result) setStatus(result);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void refresh();
  }, []);
  return (
    <div className="space-y-5">
      <div className="flex justify-between">
        <h1 className="text-xl font-bold">System health</h1>
        <button className="border rounded px-4 py-2" disabled={busy} onClick={refresh}>
          {busy ? 'Checking…' : 'Refresh'}
        </button>
      </div>
      {!status ? (
        <p>Health data is not yet available.</p>
      ) : (
        <>
          <div className="grid md:grid-cols-3 gap-4">
            {[
              ['Database', `${status.database} · ${status.databaseLatencyMs} ms`],
              [
                'Worker heartbeat',
                status.workerHeartbeat
                  ? new Date(status.workerHeartbeat).toLocaleString()
                  : 'No worker heartbeat',
              ],
              ['SMTP', status.smtpConfigured ? 'Configured' : 'Not configured'],
              ['Process uptime', `${status.uptimeSeconds} seconds`],
              ['Heap usage', `${Math.round(status.heapBytes / 1024 / 1024)} MiB`],
              [
                'Last scheduled run',
                status.lastScheduledRun ? new Date(status.lastScheduledRun).toLocaleString() : 'Not yet run',
              ],
            ].map(([name, value]) => (
              <div key={name} className="border border-zinc-700 rounded-xl p-5">
                <h2 className="text-sm text-zinc-400">{name}</h2>
                <p className="mt-2">{value}</p>
              </div>
            ))}
          </div>
          <h2 className="font-semibold">Delivery queue</h2>
          <ul>
            {status.backlog.length ? (
              status.backlog.map((row: any) => (
                <li key={row.status}>
                  {row.status}: {row.count}
                </li>
              ))
            ) : (
              <li>No deliveries queued.</li>
            )}
          </ul>
          <p className="text-sm text-zinc-400">
            Clock synchronization: {status.ntp}. HTTPS{' '}
            {status.httpsRequired ? 'required' : 'development mode'}. CSRF and outbound address validation
            enforced by the server.
          </p>
          <p className="text-xs">Checked {new Date(status.checkedAt).toLocaleString()}</p>
        </>
      )}
    </div>
  );
}
