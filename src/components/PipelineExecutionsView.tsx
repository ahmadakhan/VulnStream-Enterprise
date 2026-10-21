import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import {
  Play,
  RotateCw,
  Clock,
  CheckCircle2,
  Download,
  Terminal,
  Activity,
  Layers,
  Cpu,
  History,
  ChevronRight,
  Radio,
  Filter,
  Sparkles,
  Send,
  ShieldCheck,
  AlertCircle,
  ArrowRight,
  Maximize2,
} from 'lucide-react';
import { PipelineExecution, PipelinePhase } from '../types';
import { Pagination } from './Pagination';

export const PipelineExecutionsView: React.FC = () => {
  const { executions, isPipelineRunning, currentPipelinePhase, triggerPipelineRun, settings } = useApp();

  const [selectedExecution, setSelectedExecution] = useState<PipelineExecution | null>(null);
  const [scopeHours, setScopeHours] = useState(settings.scopeHours);
  const [selectedPhaseIdx, setSelectedPhaseIdx] = useState<number | null>(null);

  // Pagination for executions history list
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(5);

  const activeExecution = executions.find((e) => e.id === selectedExecution?.id) || executions[0] || null;

  const paginatedExecutions = executions.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleRun = async () => {
    const res = await triggerPipelineRun(scopeHours);
    setSelectedExecution(res);
  };

  const handleDownloadReport = (exec: PipelineExecution) => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(exec, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `pipeline-report-${exec.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Render persisted phases rather than attaching unrelated metrics to fixed stage indices.
  const pipelineStages = (activeExecution?.phases || []).map((phase, idx) => ({
    idx,
    phaseNumber: idx + 1,
    title: phase.name,
    subtitle: phase.details,
    icon: phase.name === 'Feed ingestion' ? Radio : phase.name === 'Delivery queue' ? Send : Cpu,
    metricLabel: 'Measured duration',
    getMetric: (_exec: PipelineExecution) => `${phase.durationMs} ms`,
    description: phase.details,
  }));

  const filteredLogs = activeExecution
    ? selectedPhaseIdx !== null
      ? activeExecution.logs.filter((l) => {
          const phaseName = activeExecution.phases[selectedPhaseIdx]?.name.toLowerCase() || '';
          return l.toLowerCase().includes(phaseName) || l.includes(`Phase ${selectedPhaseIdx + 1}`);
        })
      : activeExecution.logs
    : [];

  return (
    <div className="space-y-6">
      {/* Header and Manual Execution Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 tracking-tight flex items-center gap-2">
            <Activity className="w-5 h-5 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
            Autonomous Pipeline Executions &amp; Telemetry
          </h1>
          <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-1">
            Server-side scheduled runs persist across browser sessions. Failed deliveries remain visible for
            retry.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <div className="flex items-center space-x-1.5 text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-3 py-1.5 rounded-xl shadow-sm">
            <span>Ingestion window:</span>
            <select
              value={scopeHours}
              onChange={(e) => setScopeHours(Number(e.target.value))}
              disabled={isPipelineRunning}
              className="bg-transparent text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono font-medium focus:outline-none"
            >
              <option value={6}>6 Hours</option>
              <option value={12}>12 Hours</option>
              <option value={24}>24 Hours (Default)</option>
              <option value={48}>48 Hours</option>
              <option value={72}>72 Hours</option>
            </select>
          </div>

          <button
            onClick={handleRun}
            disabled={isPipelineRunning}
            className="text-xs px-4 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition flex items-center space-x-2 disabled:opacity-50 shadow-sm"
          >
            {isPipelineRunning ? (
              <>
                <RotateCw className="w-3.5 h-3.5 animate-spin text-zinc-600" />
                <span>Running Pipeline...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Pipeline</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* GRAPHICAL STAGE EXECUTION PIPELINE FLOWCHART DAG */}
      <div className="bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm space-y-4 transition-colors">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 pb-3">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-emerald-400" />
            <h2 className="text-xs font-bold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider font-mono">
              Graphical Stage Execution DAG &amp; Status
            </h2>
          </div>
          <div className="flex items-center space-x-3 text-xs font-mono text-zinc-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>Click any stage to filter telemetry</span>
            </span>
            {selectedPhaseIdx !== null && (
              <button
                onClick={() => setSelectedPhaseIdx(null)}
                className="text-[10px] text-zinc-400 hover:text-zinc-200 underline"
              >
                Clear Filter
              </button>
            )}
          </div>
        </div>

        {/* The Graphical Flowchart Canvas */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 relative py-2">
          {!pipelineStages.length && (
            <p className="text-sm text-zinc-400">
              {activeExecution
                ? `Execution ${activeExecution.status.toLowerCase()}; phase measurements appear when available.`
                : 'No pipeline executions yet.'}
            </p>
          )}
          {pipelineStages.map((stage, idx) => {
            const PhaseIcon = stage.icon;
            const phaseData: PipelinePhase | undefined = activeExecution?.phases[idx];
            const isPhaseSelected = selectedPhaseIdx === idx;
            const isPhaseActiveInRun =
              isPipelineRunning &&
              currentPipelinePhase?.toLowerCase().includes(stage.title.toLowerCase().slice(0, 5));

            let statusLabel = 'PENDING';
            let statusColor = 'text-zinc-500 border-zinc-800 bg-zinc-900/50';

            if (isPhaseActiveInRun) {
              statusLabel = 'RUNNING';
              statusColor = 'text-amber-400 border-amber-500/80 bg-amber-950/40 animate-pulse';
            } else if (phaseData) {
              if (phaseData.status === 'SUCCESS') {
                statusLabel = 'COMPLETED';
                statusColor = 'text-emerald-400 border-emerald-800/80 bg-emerald-950/40';
              } else if (phaseData.status === 'WARNING') {
                statusLabel = 'WARNING';
                statusColor = 'text-amber-400 border-amber-800/80 bg-amber-950/40';
              } else if (phaseData.status === 'FAILED') {
                statusLabel = 'FAILED';
                statusColor = 'text-rose-400 border-rose-800/80 bg-rose-950/40';
              }
            }

            return (
              <div key={stage.phaseNumber} className="relative group">
                {/* Node Box */}
                <div
                  onClick={() => setSelectedPhaseIdx(isPhaseSelected ? null : idx)}
                  className={`cursor-pointer rounded-2xl p-4 border transition-all duration-200 h-full flex flex-col justify-between ${
                    isPhaseSelected
                      ? 'bg-zinc-800/90 dark:bg-zinc-800/90 light:bg-zinc-200 border-zinc-500 shadow-md ring-1 ring-zinc-400'
                      : isPhaseActiveInRun
                        ? 'bg-zinc-950 dark:bg-zinc-950 light:bg-white border-amber-500/60 shadow-lg'
                        : 'bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-50 border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 hover:border-zinc-600 dark:hover:border-zinc-600 light:hover:border-zinc-400 hover:bg-zinc-900/60'
                  }`}
                >
                  {/* Top node header */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-1.5">
                        <span className="w-5 h-5 rounded-lg bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-700/80 dark:border-zinc-700/80 light:border-zinc-300 text-[10px] font-mono font-bold flex items-center justify-center text-zinc-200 dark:text-zinc-200 light:text-zinc-800">
                          {stage.phaseNumber}
                        </span>
                        <span className="text-[10px] font-mono font-semibold text-zinc-400 uppercase tracking-wider">
                          Stage {stage.phaseNumber}
                        </span>
                      </div>

                      <PhaseIcon
                        className={`w-4 h-4 ${isPhaseActiveInRun ? 'text-amber-400 animate-spin' : 'text-zinc-400 dark:text-zinc-400 light:text-zinc-600'}`}
                      />
                    </div>

                    <div className="font-bold text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 leading-snug">
                      {stage.title}
                    </div>
                    <div className="text-[10px] text-zinc-400 dark:text-zinc-400 light:text-zinc-500 font-mono mt-0.5">
                      {stage.subtitle}
                    </div>
                  </div>

                  {/* Bottom node metrics & status badge */}
                  <div className="mt-3 pt-2.5 border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] font-mono">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[9px] font-bold border uppercase tracking-wider ${statusColor}`}
                      >
                        {statusLabel}
                      </span>
                      <span className="text-zinc-400 font-medium">
                        {phaseData ? `${phaseData.durationMs}ms` : '—'}
                      </span>
                    </div>

                    <div className="text-[10px] font-mono text-zinc-300 dark:text-zinc-300 light:text-zinc-700 truncate">
                      {activeExecution ? stage.getMetric(activeExecution) : 'Standby'}
                    </div>
                  </div>
                </div>

                {/* Flow Directional Arrow (Hidden on Last Stage or Mobile) */}
                {idx < 4 && (
                  <div className="hidden md:flex absolute -right-2 top-1/2 -translate-y-1/2 z-10 w-4 h-4 rounded-full bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 items-center justify-center shadow-sm">
                    <ArrowRight className="w-2.5 h-2.5 text-zinc-400" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Execution History Selector Bar */}
      {executions.length > 0 && (
        <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 shadow-sm transition-colors">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              <History className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              <h3 className="text-xs font-bold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider font-mono">
                Recent Pipeline Runs History
              </h3>
            </div>
            <span className="text-[11px] font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
              {executions.length} Total Executions Recorded
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
            {paginatedExecutions.map((exec) => {
              const isSelected = activeExecution?.id === exec.id;
              return (
                <div
                  key={exec.id}
                  onClick={() => {
                    setSelectedExecution(exec);
                    setSelectedPhaseIdx(null);
                  }}
                  className={`cursor-pointer p-2.5 rounded-xl border text-xs font-mono transition ${
                    isSelected
                      ? 'bg-zinc-800 border-zinc-600 text-zinc-100 dark:bg-zinc-800 dark:border-zinc-600 dark:text-zinc-100 light:bg-zinc-200 light:border-zinc-400 light:text-zinc-900 font-bold shadow-sm'
                      : 'bg-zinc-950/60 border-zinc-800/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60 dark:bg-zinc-950/60 dark:border-zinc-800/80 light:bg-zinc-50 light:border-zinc-200 light:text-zinc-600 light:hover:text-zinc-900 light:hover:bg-zinc-100'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[11px]">{exec.id}</span>
                    <span className="text-[10px] text-emerald-400 font-semibold">{exec.status}</span>
                  </div>
                  <div className="text-[10px] text-zinc-500 light:text-zinc-600 font-sans mt-1">
                    {new Date(exec.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}{' '}
                    • {exec.stats.matchedWatchlist} Matches
                  </div>
                </div>
              );
            })}
          </div>

          {executions.length > 5 && (
            <div className="mt-3 pt-2 border-t border-zinc-800/60 dark:border-zinc-800/60 light:border-zinc-200">
              <Pagination
                currentPage={currentPage}
                totalItems={executions.length}
                pageSize={pageSize}
                onPageChange={setCurrentPage}
                onPageSizeChange={setPageSize}
                pageSizeOptions={[5, 10, 20]}
              />
            </div>
          )}
        </div>
      )}

      {/* Main Execution Inspector */}
      {activeExecution ? (
        <div className="space-y-6">
          {/* Executive Metrics Bar */}
          <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm transition-colors">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
              <div className="flex items-center space-x-3">
                <span className="font-mono font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 text-sm">
                  Run: {activeExecution.id}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 font-medium">
                  {activeExecution.status}
                </span>
                <span className="text-xs font-mono text-zinc-500 dark:text-zinc-500 light:text-zinc-600">
                  Ingestion window: {activeExecution.scopeHours}h; matching evaluates all cached CVEs
                </span>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleDownloadReport(activeExecution)}
                  className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 flex items-center space-x-1.5 transition font-medium"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download JSON Report</span>
                </button>
              </div>
            </div>

            {/* Ingestion Metric Counters */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
              <div className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
                <div className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 text-[11px]">
                  Feed Records Read
                </div>
                <div className="font-mono font-bold text-zinc-200 dark:text-zinc-200 light:text-zinc-900 text-lg mt-0.5">
                  {activeExecution.stats.rawIngested}
                </div>
              </div>
              <div className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
                <div className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 text-[11px]">
                  Normalized CVEs
                </div>
                <div className="font-mono font-bold text-zinc-200 dark:text-zinc-200 light:text-zinc-900 text-lg mt-0.5">
                  {activeExecution.stats.normalized}
                </div>
              </div>
              <div className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
                <div className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 text-[11px]">
                  Duplicates Dropped
                </div>
                <div className="font-mono font-bold text-zinc-400 dark:text-zinc-400 light:text-zinc-700 text-lg mt-0.5">
                  {activeExecution.stats.inRunDuplicatesDropped}
                </div>
              </div>
              <div className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
                <div className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 text-[11px]">
                  Product Matches
                </div>
                <div className="font-mono font-bold text-zinc-200 dark:text-zinc-200 light:text-zinc-900 text-lg mt-0.5">
                  {activeExecution.stats.matchedWatchlist}
                </div>
              </div>
              <div className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
                <div className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 text-[11px]">
                  Notifications Queued
                </div>
                <div className="font-mono font-bold text-emerald-400 text-lg mt-0.5">
                  {activeExecution.stats.notificationsQueued ?? 0}
                </div>
              </div>
              <div className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
                <div className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 text-[11px]">
                  Advisories Queued
                </div>
                <div className="font-mono font-bold text-zinc-200 dark:text-zinc-200 light:text-zinc-900 text-lg mt-0.5">
                  {activeExecution.stats.advisoriesQueued ?? 0}
                </div>
              </div>
            </div>
          </div>

          {/* Phase-by-Phase Detailed Telemetry */}
          <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm space-y-3 transition-colors">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-zinc-300 dark:text-zinc-300 light:text-zinc-800 uppercase tracking-wider flex items-center gap-2">
                <Layers className="w-4 h-4 text-zinc-400" />
                Phase Telemetry Breakdown
              </h3>
              {selectedPhaseIdx !== null && (
                <span className="text-[11px] font-mono text-emerald-400">
                  Filtering on Stage {selectedPhaseIdx + 1}: {activeExecution.phases[selectedPhaseIdx]?.name}
                </span>
              )}
            </div>

            <div className="space-y-2">
              {activeExecution.phases.map((phase, idx) => {
                const isSelected = selectedPhaseIdx === idx;
                return (
                  <div
                    key={idx}
                    onClick={() => setSelectedPhaseIdx(isSelected ? null : idx)}
                    className={`cursor-pointer rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs border transition ${
                      isSelected
                        ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 border-zinc-500 shadow-sm'
                        : 'bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border-zinc-800 dark:border-zinc-800 light:border-zinc-200 hover:border-zinc-700'
                    }`}
                  >
                    <div className="flex items-start space-x-3">
                      <span className="w-6 h-6 rounded-full bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-mono text-[11px] flex items-center justify-center shrink-0 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300">
                        {idx + 1}
                      </span>
                      <div>
                        <div className="font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-900 flex items-center space-x-2">
                          <span>{phase.name}</span>
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        </div>
                        <div className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[11px] mt-0.5">
                          {phase.details}
                        </div>
                      </div>
                    </div>

                    <div className="sm:text-right shrink-0 font-mono text-[11px]">
                      <span className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600">Duration: </span>
                      <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-medium">
                        {phase.durationMs}ms
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Execution Log Stream */}
          <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm transition-colors">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-zinc-400" />
                <h3 className="text-xs font-semibold text-zinc-300 dark:text-zinc-300 light:text-zinc-800 uppercase tracking-wider">
                  Live Execution Log Stream
                </h3>
              </div>
              <span className="text-[11px] font-mono text-zinc-500">
                {filteredLogs.length} Entries {selectedPhaseIdx !== null ? `(Filtered)` : ''}
              </span>
            </div>

            <div className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-xl p-4 font-mono text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-700 space-y-1 max-h-56 overflow-y-auto leading-relaxed">
              {filteredLogs.length === 0 ? (
                <div className="text-zinc-500 py-2">No log entries found for this specific filter.</div>
              ) : (
                filteredLogs.map((log, i) => (
                  <div
                    key={i}
                    className="hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
                  >
                    {log}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-12 text-center text-zinc-500 text-xs">
          <Clock className="w-8 h-8 text-zinc-600 mx-auto mb-3" />
          <p className="font-medium text-zinc-300 dark:text-zinc-300 light:text-zinc-800">
            No executions recorded yet this session.
          </p>
          <p className="text-[11px] text-zinc-500 mt-1">
            Click &quot;Run Pipeline&quot; above to execute automated ingestion.
          </p>
        </div>
      )}
    </div>
  );
};
