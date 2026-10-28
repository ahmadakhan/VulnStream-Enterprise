import { PageHeading } from './PageHeading';
import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { AliasEntry } from '../types';
import { DEFAULT_VENDOR_ALIASES, DEFAULT_PRODUCT_ALIASES } from '../utils/cpeMatcher';
import { Tags, Plus, Trash2, Pencil, X, Search, AlertCircle, Lock, Info, ShieldCheck, Ban, Clock } from 'lucide-react';
import { formatDate as fmtDate, formatDateTime as fmtDateTime } from '../utils/dateTime';

export const AliasesView: React.FC = () => {
  const { aliases, addAlias, updateAlias, deleteAlias, promoteAlias, revokeAlias, session } = useApp();
  const admin = session?.role === 'ADMIN';

  const [activeTab, setActiveTab] = useState<'VENDOR' | 'PRODUCT'>('VENDOR');
  const [searchTerm, setSearchTerm] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [editing, setEditing] = useState<AliasEntry | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [form, setForm] = useState({ canonical: '', aliasText: '', notes: '' });

  const defaultsForTab = activeTab === 'VENDOR' ? DEFAULT_VENDOR_ALIASES : DEFAULT_PRODUCT_ALIASES;
  const customForTab = aliases.filter((a) => a.scope === activeTab);

  const term = searchTerm.toLowerCase();
  const aliasesFor = (entry: AliasEntry) =>
    entry.source === 'REVOKED' ? entry.revokedAliases ?? [] : entry.aliases;
  const filteredCustom = customForTab.filter(
    (a) => a.canonical.toLowerCase().includes(term) || aliasesFor(a).some((x) => x.toLowerCase().includes(term)),
  );
  const filteredDefaults = Object.entries(defaultsForTab).filter(
    ([canonical, list]) =>
      canonical.toLowerCase().includes(term) || list.some((x) => x.toLowerCase().includes(term)),
  );

  const openAdd = () => {
    setEditing(null);
    setForm({ canonical: '', aliasText: '', notes: '' });
    setErrorMsg(null);
    setShowModal(true);
  };
  const openEdit = (entry: AliasEntry) => {
    setEditing(entry);
    setForm({ canonical: entry.canonical, aliasText: entry.aliases.join(', '), notes: entry.notes || '' });
    setErrorMsg(null);
    setShowModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    const canonical = form.canonical.trim();
    const aliasList = Array.from(
      new Set(
        form.aliasText
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      ),
    );
    if (!canonical) {
      setErrorMsg('Canonical name is required.');
      return;
    }
    if (!aliasList.length) {
      setErrorMsg('Add at least one alias.');
      return;
    }
    const payload = {
      scope: activeTab,
      canonical,
      aliases: aliasList,
      notes: form.notes.trim() || undefined,
    };
    const ok = editing ? await updateAlias({ ...editing, ...payload }) : await addAlias(payload);
    if (ok) {
      setShowModal(false);
      setEditing(null);
    } else {
      setErrorMsg('Could not save this alias. Check the fields and try again.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="ui-page-header">
        <PageHeading page="aliases">
          Vendor and product name synonyms the matching engine uses to correlate inventory with CVE
          identifiers when a strict CPE/PURL match isn't available.
        </PageHeading>
        {admin ? (
          <button
            onClick={openAdd}
            className="text-xs px-3.5 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition flex items-center space-x-1.5 shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Alias</span>
          </button>
        ) : (
          <div className="text-[11px] text-zinc-500 flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5" />
            Administrator role required to edit
          </div>
        )}
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-200 pb-3">
        <div className="flex items-center space-x-1.5 bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-1 rounded-xl w-fit">
          {(['VENDOR', 'PRODUCT'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition ${
                activeTab === tab
                  ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                  : 'text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900'
              }`}
            >
              {tab === 'VENDOR' ? 'Vendor Aliases' : 'Product Aliases'}
            </button>
          ))}
        </div>
        <div className="relative w-full sm:w-56">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search aliases..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-lg pl-8 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
          />
        </div>
      </div>

      <div>
        <h2 className="text-[11px] font-semibold uppercase tracking-wide text-zinc-500 mb-2">
          Managed {activeTab === 'VENDOR' ? 'vendor' : 'product'} aliases ({filteredCustom.length})
        </h2>
        {errorMsg && !showModal && (
          <div className="mb-2 p-2.5 bg-zinc-950 border border-rose-800/60 rounded-xl text-xs text-rose-300 flex items-center space-x-1.5">
            <AlertCircle className="w-4 h-4" />
            <span>{errorMsg}</span>
          </div>
        )}
        {filteredCustom.length === 0 ? (
          <div className="rounded-xl border border-dashed border-zinc-800 dark:border-zinc-800 light:border-zinc-300 p-6 text-center text-xs text-zinc-500">
            No managed aliases yet{searchTerm ? ' matching your search' : ''}.
          </div>
        ) : (
          <div className="rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 divide-y divide-zinc-800 dark:divide-zinc-800 light:divide-zinc-200 overflow-hidden">
            {filteredCustom.map((entry) => (
              <div
                key={entry.id}
                className="flex items-start justify-between gap-4 p-3.5 bg-zinc-900/40 dark:bg-zinc-900/40 light:bg-white"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                      {entry.canonical}
                    </span>
                    {entry.source === 'AUTO' && (
                      <span
                        className="text-[9px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                        title={
                          entry.provenance === 'CONFIRMED_CORRELATION'
                            ? 'Learned from a confirmed correlation; expires without fresh evidence unless promoted'
                            : 'Derived from the inventory record and its CPE identity; expires without fresh evidence unless promoted'
                        }
                      >
                        Auto
                      </span>
                    )}
                    {entry.source === 'REVOKED' && (
                      <span
                        className="text-[9px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded-md bg-red-500/10 text-red-400 border border-red-500/20"
                        title="Operator revocation: this relation is never used for matching and will not be re-learned"
                      >
                        Revoked
                      </span>
                    )}
                    {entry.source === 'AUTO' && entry.provenance && (
                      <span
                        className="text-[9px] uppercase tracking-wide px-1.5 py-0.5 rounded-md bg-zinc-800 light:bg-zinc-100 text-zinc-400"
                        title={[
                          entry.provenance === 'CONFIRMED_CORRELATION' ? 'Correlation evidence' : 'Inventory evidence',
                          entry.firstSeenAt ? `first learned ${new Date(entry.firstSeenAt).toLocaleString()}` : '',
                          entry.evidenceCount ? `${entry.evidenceCount} confirmed finding(s)` : '',
                        ]
                          .filter(Boolean)
                          .join(' · ')}
                      >
                        {entry.provenance === 'CONFIRMED_CORRELATION' ? 'Correlation' : 'Inventory'}
                        {entry.evidenceCount && entry.evidenceCount > 1 ? ` ×${entry.evidenceCount}` : ''}
                      </span>
                    )}
                    {entry.source === 'AUTO' && entry.expiresAt && (
                      <span
                        className="text-[9px] text-zinc-500 flex items-center gap-1"
                        title="Automatic rows are removed when this date passes without fresh evidence"
                      >
                        <Clock className="w-3 h-3" />
                        {new Date(entry.expiresAt).toLocaleDateString()}
                      </span>
                    )}
                    <span className="text-zinc-600">&rarr;</span>
                    {(entry.source === 'REVOKED' ? entry.revokedAliases ?? [] : entry.aliases).map((a) => (
                      <span
                        key={a}
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded-md bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-100 ${
                          entry.source === 'REVOKED'
                            ? 'text-red-300 line-through'
                            : 'text-zinc-300 dark:text-zinc-300 light:text-zinc-700'
                        }`}
                      >
                        {a}
                      </span>
                    ))}
                  </div>
                  {entry.notes && <p className="text-[11px] text-zinc-500 mt-1.5">{entry.notes}</p>}
                </div>
                {admin && (
                  <div className="flex items-center gap-1 shrink-0">
                    {entry.source === 'AUTO' && (
                      <>
                        <button
                          onClick={async () => {
                            if (!(await promoteAlias(entry.id)))
                              setErrorMsg('Could not promote this alias.');
                          }}
                          className="p-1.5 rounded-lg text-zinc-400 hover:text-emerald-400 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 transition"
                          title="Promote to a permanent operator alias"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={async () => {
                            if (!(await revokeAlias(entry.id)))
                              setErrorMsg('Could not revoke this alias.');
                          }}
                          className="p-1.5 rounded-lg text-zinc-400 hover:text-red-400 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 transition"
                          title="Revoke: stop using and re-learning this relation"
                        >
                          <Ban className="w-3.5 h-3.5" />
                        </button>
                      </>
                    )}
                    {entry.source !== 'AUTO' && entry.source !== 'REVOKED' && (
                      <button
                        onClick={() => openEdit(entry)}
                        className="p-1.5 rounded-lg text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 transition"
                        title="Edit"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                    )}
                    <button
                      onClick={() => setDeletingId(entry.id)}
                      className="p-1.5 rounded-lg text-zinc-400 hover:text-red-400 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 transition"
                      title={
                        entry.source === 'REVOKED'
                          ? 'Delete the revocation (allows automatic re-learning)'
                          : 'Delete'
                      }
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
        <p className="text-[11px] text-zinc-500 mt-2 flex items-start gap-1.5">
          <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
          Inventory aliases come from each active asset&rsquo;s declared vendor/product and its own CPE spellings.
          Correlation aliases are learned only from findings that were auto-dispatched, delivered, or resolved by an
          operator &mdash; never from unreviewed text matches. Automatic rows expire 30 days after their last
          supporting evidence; promote one to keep it permanently, or revoke it to block re-learning. Operator
          aliases are never changed automatically.
        </p>
      </div>

      <div>
        <h2 className="text-[11px] font-semibold uppercase tracking-wide text-zinc-500 mb-2 flex items-center gap-1.5">
          <Lock className="w-3 h-3" />
          Built-in baseline ({filteredDefaults.length}) &mdash; not editable here
        </h2>
        <div className="rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 divide-y divide-zinc-800 dark:divide-zinc-800 light:divide-zinc-200 overflow-hidden opacity-80">
          {filteredDefaults.map(([canonical, list]) => (
            <div
              key={canonical}
              className="flex items-center gap-2 flex-wrap p-3 bg-zinc-900/20 dark:bg-zinc-900/20 light:bg-zinc-50"
            >
              <span className="text-xs font-mono font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-800">
                {canonical}
              </span>
              <span className="text-zinc-600">&rarr;</span>
              {list.map((a) => (
                <span
                  key={a}
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded-md bg-zinc-800/60 dark:bg-zinc-800/60 light:bg-zinc-100 text-zinc-400 dark:text-zinc-400 light:text-zinc-600"
                >
                  {a}
                </span>
              ))}
            </div>
          ))}
        </div>
        <p className="text-[11px] text-zinc-500 mt-2 flex items-start gap-1.5">
          <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
          These ship with the matching engine and are code-reviewed for correctness. Custom aliases above add
          to this list &mdash; they can't remove or override a built-in mapping.
        </p>
      </div>

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setShowModal(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-bold text-zinc-100 mb-1 flex items-center gap-2">
              <Tags className="w-4 h-4 text-zinc-300" />
              {editing ? 'Edit' : 'Add'} {activeTab === 'VENDOR' ? 'Vendor' : 'Product'} Alias
            </h2>
            <p className="text-xs text-zinc-400 mb-4">
              Map alternate names a CVE's CPE/PURL might use to the canonical name your inventory uses.
            </p>

            {errorMsg && (
              <div className="mb-3 p-2.5 bg-zinc-950 border border-rose-800/60 rounded-xl text-xs text-rose-300 flex items-center space-x-1.5">
                <AlertCircle className="w-4 h-4" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Canonical name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. pan_os"
                  value={form.canonical}
                  onChange={(e) => setForm({ ...form, canonical: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono text-[11px] focus:border-zinc-600 focus:outline-none"
                />
                <p className="text-[10px] text-zinc-500 mt-1">
                  The name as it appears in a CVE's CPE or PURL{' '}
                  {activeTab === 'VENDOR' ? 'vendor' : 'product'} field.
                </p>
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Aliases *</label>
                <input
                  type="text"
                  required
                  placeholder="comma-separated, e.g. panos, pan-os"
                  value={form.aliasText}
                  onChange={(e) => setForm({ ...form, aliasText: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono text-[11px] focus:border-zinc-600 focus:outline-none"
                />
                <p className="text-[10px] text-zinc-500 mt-1">
                  Alternate names your inventory might use that should resolve to the canonical name above.
                </p>
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Notes</label>
                <textarea
                  rows={2}
                  placeholder="Optional context for other operators"
                  value={form.notes}
                  onChange={(e) => setForm({ ...form, notes: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 focus:border-zinc-600 focus:outline-none resize-none"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 text-zinc-900 font-semibold"
                >
                  {editing ? 'Save Changes' : 'Add Alias'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {deletingId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl">
            <h3 className="text-sm font-bold text-zinc-100 mb-2">Remove this alias?</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-6">
              The matching engine will stop treating these names as equivalent. This does not affect existing
              findings.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                onClick={() => setDeletingId(null)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  const deleted = await deleteAlias(deletingId);
                  if (deleted) setDeletingId(null);
                }}
                className="px-3 py-1.5 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold"
              >
                Remove
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
