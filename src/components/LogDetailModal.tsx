import React from 'react';
import { X } from 'lucide-react';

export interface LogDetailField {
  label: string;
  value: React.ReactNode;
  /** Render the value in the monospace/code font. */
  mono?: boolean;
  /** Render the value as a wrapped, scrollable block instead of a single line
   * (long text, JSON, hashes). */
  block?: boolean;
  /** Only render this field when it has a meaningful value. */
  hidden?: boolean;
}

const LEVEL_BADGE: Record<'INFO' | 'WARNING' | 'ERROR', string> = {
  INFO: 'border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700',
  WARNING: 'border-amber-500/20 bg-amber-500/10 text-amber-400 light:text-amber-700',
  ERROR: 'border-rose-500/20 bg-rose-500/10 text-rose-400 light:text-rose-700',
};

interface LogDetailModalProps {
  icon: React.ReactNode;
  eyebrow: string;
  title: string;
  level: 'INFO' | 'WARNING' | 'ERROR';
  timestamp: string;
  fields: LogDetailField[];
  onClose: () => void;
}

/** Theme-aware detail popup for a single operational-log or audit-trail row.
 * Matches the modal chrome used throughout the app (RecipientsView,
 * ThreatFeedsView, AliasesView): dark zinc card with light-mode overrides,
 * no backdrop-click or Escape close, just the explicit close button. */
export const LogDetailModal: React.FC<LogDetailModalProps> = ({
  icon,
  eyebrow,
  title,
  level,
  timestamp,
  fields,
  onClose,
}) => (
  <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
    <div className="relative w-full max-w-2xl rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl light:border-zinc-200 light:bg-white">
      <button
        onClick={onClose}
        aria-label="Close"
        className="absolute right-4 top-4 text-zinc-500 transition hover:text-zinc-200 light:hover:text-zinc-900"
      >
        <X className="h-5 w-5" />
      </button>

      <div className="flex items-start gap-3 pr-8">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-zinc-700/80 bg-zinc-800/60 text-zinc-300 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-700">
          {icon}
        </span>
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">{eyebrow}</p>
          <h2 className="mt-0.5 break-words text-sm font-semibold text-zinc-100 light:text-zinc-900">{title}</h2>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold ${LEVEL_BADGE[level]}`}>
          {level}
        </span>
        <span className="text-[11px] text-zinc-500">
          {new Intl.DateTimeFormat(undefined, {
            dateStyle: 'medium',
            timeStyle: 'medium',
            timeZone: 'UTC',
          }).format(new Date(timestamp))}{' '}
          UTC
        </span>
      </div>

      <dl className="mt-5 max-h-[60vh] space-y-3.5 overflow-y-auto pr-1 text-xs">
        {fields
          .filter((f) => !f.hidden)
          .map((field) => (
            <div key={field.label}>
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">{field.label}</dt>
              <dd
                className={
                    field.block
                      ? `mt-1.5 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-zinc-700/50 bg-zinc-950/80 p-3 text-[11px] leading-relaxed text-zinc-300 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-700 ${field.mono ? 'font-mono' : ''}`
                      : `mt-1 break-words text-[12px] text-zinc-200 light:text-zinc-800 ${field.mono ? 'font-mono' : ''}`
                }
              >
                {field.value}
              </dd>
            </div>
          ))}
      </dl>
    </div>
  </div>
);
