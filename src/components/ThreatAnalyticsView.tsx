import { PageHeading } from './PageHeading';
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useApp } from '../context/AppContext';
import {
  ThreatAnalytics,
  TimelinePoint,
  SeverityDistribution,
  ExploitStatusDistribution,
  VendorAnalytics,
  CveScoreBin,
} from '../types';
import {
  BarChart3,
  RefreshCw,
  Download,
  Copy,
  Check,
  Loader2,
  Calendar,
  TrendingUp,
  Flame,
  Database,
  AlertCircle,
} from 'lucide-react';
import { copyText } from '../utils/clipboard';

const DATE_FORMATTER = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const formatDate = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : DATE_FORMATTER.format(date);
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#22c55e',
  UNKNOWN: '#9ca3af',
};

const SEVERITY_LABELS: Record<keyof SeverityDistribution, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  unknown: 'Unknown',
};

const EXPLOIT_LABELS: Record<keyof ExploitStatusDistribution, string> = {
  activeWeaponized: 'Active Weaponized',
  reportedInWild: 'Reported In Wild',
  pocAvailable: 'PoC Available',
  none: 'No Known Exploit',
};

const TIMELINE_OPTIONS: { value: string; label: string }[] = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: '365d', label: 'Last 365 days' },
  { value: 'all', label: 'All time' },
];

const SCORE_COLORS = ['#6b7280', '#3b82f6', '#f59e0b', '#f97316', '#ef4444'];

function BarChart({
  data,
  maxValue,
  color,
  unit = '',
  showLabels = true,
}: {
  data: { label: string; value: number }[];
  maxValue: number;
  color?: string;
  unit?: string;
  showLabels?: boolean;
}) {
  const barHeight = 120;
  const barWidth = 32;
  const gap = 12;
  const totalWidth = data.length * (barWidth + gap);
  return (
    <svg
      width={Math.max(totalWidth + 40, 200)}
      height={barHeight + 40}
      viewBox={`0 0 ${totalWidth + 40} ${barHeight + 40}`}
    >
      <g transform={`translate(20, ${barHeight})`}>
        {data.map((d, i) => {
          const height = maxValue > 0 ? (d.value / maxValue) * barHeight : 0;
          const x = i * (barWidth + gap);
          return (
            <g key={d.label} transform={`translate(${x}, 0)`}>
              <rect
                x={0}
                y={-height}
                width={barWidth}
                height={height}
                rx={2}
                fill={color || SEVERITY_COLORS[d.label.split(' ').pop()?.toUpperCase() || 'CRITICAL']}
                opacity={0.85}
              />
              <text
                x={barWidth / 2}
                y={-height - 4}
                textAnchor="middle"
                fontSize={11}
                fill="currentColor"
                className="text-zinc-400 light:text-zinc-600"
              >
                {d.value > 0 ? `${d.value}${unit}` : ''}
              </text>
              {showLabels && (
                <text
                  x={barWidth / 2}
                  y={18}
                  textAnchor="middle"
                  fontSize={10}
                  fill="currentColor"
                  className="text-zinc-500 light:text-zinc-600"
                >
                  {d.label}
                </text>
              )}
            </g>
          );
        })}
      </g>
      <line
        x1={20}
        y1={barHeight}
        x2={totalWidth + 20}
        y2={barHeight}
        stroke="currentColor"
        strokeWidth={1}
        opacity={0.2}
      />
    </svg>
  );
}

function TimelineChart({ data }: { data: TimelinePoint[] }) {
  const maxValue = Math.max(...data.map((d) => d.cveCount), 1);
  const chartHeight = 120;
  const chartWidth = 560;
  const padding = { top: 10, right: 20, bottom: 40, left: 40 };
  const plotWidth = chartWidth - padding.left - padding.right;
  const plotHeight = chartHeight - padding.top - padding.bottom;

  const yScale = (value: number) => plotHeight - (value / maxValue) * plotHeight;

  const maxCritical = Math.max(...data.map((d) => d.critical), 1);
  const maxHigh = Math.max(...data.map((d) => d.high), 1);

  if (data.length === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-zinc-500 light:text-zinc-600">
        <Database className="h-6 w-6 mr-2" />
        <span className="text-sm">No data for the selected timeline.</span>
      </div>
    );
  }

  const barWidth = Math.max(20, (plotWidth / data.length) * 0.6);
  const barGap = (plotWidth - data.length * barWidth) / Math.max(data.length - 1, 1);

  return (
    <svg width={chartWidth} height={chartHeight} viewBox={`0 0 ${chartWidth} ${chartHeight}`}>
      <g transform={`translate(${padding.left}, ${padding.top})`}>
        <line
          x1={0}
          y1={plotHeight}
          x2={plotWidth}
          y2={plotHeight}
          stroke="currentColor"
          strokeWidth={1}
          opacity={0.2}
        />
        {data.map((d, i) => {
          const x = i * (barWidth + barGap);
          const criticalHeight = (d.critical / maxCritical) * plotHeight;
          const highHeight = (d.high / maxHigh) * plotHeight;
          return (
            <g key={d.label} transform={`translate(${x}, 0)`}>
              <rect
                x={0}
                y={plotHeight - criticalHeight}
                width={barWidth / 2}
                height={criticalHeight}
                fill={SEVERITY_COLORS.CRITICAL}
                opacity={0.8}
              />
              <rect
                x={barWidth / 2}
                y={plotHeight - highHeight}
                width={barWidth / 2}
                height={highHeight}
                fill={SEVERITY_COLORS.HIGH}
                opacity={0.8}
              />
              <text
                x={barWidth / 2}
                y={plotHeight + 16}
                textAnchor="middle"
                fontSize={10}
                fill="currentColor"
                className="text-zinc-500 light:text-zinc-600"
              >
                {d.label}
              </text>
              <text
                x={barWidth / 2}
                y={-4}
                textAnchor="middle"
                fontSize={9}
                fill="currentColor"
                className="text-zinc-400 light:text-zinc-600"
              >
                {d.cveCount}
              </text>
            </g>
          );
        })}
      </g>
    </svg>
  );
}

function PieChart({
  data,
  colors,
  size = 140,
  showLegend = true,
}: {
  data: { label: string; value: number; color?: string }[];
  colors?: string[];
  size?: number;
  showLegend?: boolean;
}) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  if (total === 0) {
    return (
      <div className="h-32 flex items-center justify-center text-zinc-500 light:text-zinc-600">
        <span className="text-sm">No data</span>
      </div>
    );
  }
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 10;

  let offset = 0;
  const slices = data.map((d, i) => {
    const percentage = d.value / total;
    const degrees = percentage * 360;
    const startAngle = offset;
    offset += degrees;
    const color =
      d.color || colors?.[i % (colors?.length || 1)] || SEVERITY_COLORS[d.label.toUpperCase()] || '#9ca3af';

    if (percentage >= 1) {
      const startRad = (startAngle - 90) * (Math.PI / 180);
      const endRad = (startAngle + degrees - 90) * (Math.PI / 180);
      const x1 = cx + r * Math.cos(startRad);
      const y1 = cy + r * Math.sin(startRad);
      const x2 = cx + r * Math.cos(endRad);
      const y2 = cy + r * Math.sin(endRad);
      const largeArc = degrees > 180 ? 1 : 0;
      return {
        path: `M ${cx},${cy} L ${x1},${y1} A ${r},${r} 0 ${largeArc} 1 ${x2},${y2} Z`,
        color,
        label: d.label,
        value: d.value,
        percentage,
      };
    }

    if (percentage === 0) return null;

    const startRad = (startAngle - 90) * (Math.PI / 180);
    const endRad = (startAngle + degrees - 90) * (Math.PI / 180);
    const x1 = cx + r * Math.cos(startRad);
    const y1 = cy + r * Math.sin(startRad);
    const x2 = cx + r * Math.cos(endRad);
    const y2 = cy + r * Math.sin(endRad);
    const largeArc = degrees > 180 ? 1 : 0;
    const path = `M ${cx},${cy} L ${x1},${y1} A ${r},${r} 0 ${largeArc} 1 ${x2},${y2} Z`;
    return { path, color, label: d.label, value: d.value, percentage };
  });

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {slices.filter(Boolean).map((s, i) =>
        s ? (
          <g key={`${s.label}-${i}`}>
            <path d={s.path} fill={s.color} opacity={0.85} />
          </g>
        ) : null,
      )}
      <text
        x={cx}
        y={cy}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize={14}
        fontWeight="bold"
        fill="currentColor"
        className="text-zinc-100 light:text-zinc-900"
      >
        {total}
      </text>
    </svg>
  );
}

function HistogramChart({ bins }: { bins: CveScoreBin[] }) {
  const maxValue = Math.max(...bins.map((b) => b.count), 1);
  const barHeight = 140;
  const barWidth = 48;
  const gap = 6;
  const totalWidth = bins.length * (barWidth + gap);
  return (
    <svg
      width={Math.max(totalWidth + 30, 240)}
      height={barHeight + 40}
      viewBox={`0 0 ${totalWidth + 30} ${barHeight + 40}`}
    >
      <g transform={`translate(15, ${barHeight})`}>
        {bins.map((bin, i) => {
          const height = (bin.count / maxValue) * barHeight;
          const x = i * (barWidth + gap);
          return (
            <g key={bin.range} transform={`translate(${x}, 0)`}>
              <rect
                x={0}
                y={-height}
                width={barWidth}
                height={height}
                rx={2}
                fill={SCORE_COLORS[i % SCORE_COLORS.length]}
                opacity={0.8}
              />
              <text
                x={barWidth / 2}
                y={-height - 3}
                textAnchor="middle"
                fontSize={10}
                fill="currentColor"
                className="text-zinc-500 light:text-zinc-600"
              >
                {bin.count > 0 ? bin.count : ''}
              </text>
              <text
                x={barWidth / 2}
                y={20}
                textAnchor="middle"
                fontSize={9}
                fill="currentColor"
                className="text-zinc-500 light:text-zinc-600"
              >
                {bin.range}
              </text>
            </g>
          );
        })}
      </g>
      <line
        x1={15}
        y1={barHeight}
        x2={totalWidth + 15}
        y2={barHeight}
        stroke="currentColor"
        strokeWidth={1}
        opacity={0.2}
      />
    </svg>
  );
}

function Legend({ items }: { items: { label: string; color: string; value: number }[] }) {
  return (
    <div className="flex flex-wrap gap-3">
      {items.map((item) => (
        <div key={item.label} className="flex flex-wrap items-center gap-2">
          <span className="w-3 h-3 rounded" style={{ backgroundColor: item.color }} />
          <span className="text-xs text-zinc-400 light:text-zinc-600">{item.label}</span>
          <span className="text-xs font-mono text-zinc-300 light:text-zinc-800">{item.value}</span>
        </div>
      ))}
    </div>
  );
}

export const ThreatAnalyticsView: React.FC = () => {
  const { fetchThreatAnalytics } = useApp();
  const [range, setRange] = useState('30d');
  const [analytics, setAnalytics] = useState<ThreatAnalytics | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const loadAnalytics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchThreatAnalytics(range, 10);
      setAnalytics(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load analytics');
    } finally {
      setLoading(false);
    }
  }, [range, fetchThreatAnalytics]);

  useEffect(() => {
    void loadAnalytics();
  }, [loadAnalytics]);

  const handleRangeChange = (newRange: string) => {
    setRange(newRange);
  };

  const handleDownload = () => {
    if (!analytics) return;
    const blob = new Blob([JSON.stringify(analytics, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-analytics-${range}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopy = async () => {
    if (!analytics) return;
    const success = await copyText(JSON.stringify(analytics, null, 2));
    setCopied(success);
    setTimeout(() => setCopied(false), 2000);
  };

  const severityData = useMemo(
    () =>
      analytics
        ? [
            {
              label: 'Critical',
              value: analytics.severityDistribution.critical,
              color: SEVERITY_COLORS.CRITICAL,
            },
            { label: 'High', value: analytics.severityDistribution.high, color: SEVERITY_COLORS.HIGH },
            { label: 'Medium', value: analytics.severityDistribution.medium, color: SEVERITY_COLORS.MEDIUM },
            { label: 'Low', value: analytics.severityDistribution.low, color: SEVERITY_COLORS.LOW },
            {
              label: 'Unknown',
              value: analytics.severityDistribution.unknown,
              color: SEVERITY_COLORS.UNKNOWN,
            },
          ]
        : [],
    [analytics],
  );

  const exploitData = useMemo(
    () =>
      analytics
        ? [
            {
              label: 'Active Weaponized',
              value: analytics.exploitStatusDistribution.activeWeaponized,
              color: SEVERITY_COLORS.CRITICAL,
            },
            {
              label: 'Reported In Wild',
              value: analytics.exploitStatusDistribution.reportedInWild,
              color: SEVERITY_COLORS.HIGH,
            },
            {
              label: 'PoC Available',
              value: analytics.exploitStatusDistribution.pocAvailable,
              color: SEVERITY_COLORS.MEDIUM,
            },
            {
              label: 'No Known Exploit',
              value: analytics.exploitStatusDistribution.none,
              color: SEVERITY_COLORS.LOW,
            },
          ]
        : [],
    [analytics],
  );

  return (
    <div className="space-y-6">
      <PageHeading
        page="threat-analytics"
        children={
          <span className="text-sm text-zinc-400 light:text-zinc-600">
            Aggregated vulnerability trends and severity distributions from the NVD CVE cache. Select a time
            range to update all charts below.
          </span>
        }
      />

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <Calendar className="h-4 w-4 text-zinc-500" />
          <span className="text-sm text-zinc-400 light:text-zinc-600">Timeline:</span>
          {TIMELINE_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              aria-pressed={range === opt.value}
              onClick={() => handleRangeChange(opt.value)}
              className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                range === opt.value
                  ? 'bg-blue-500/15 border border-blue-400/30 text-blue-300 light:text-blue-800'
                  : 'bg-zinc-800/50 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-300 light:text-zinc-700 hover:bg-zinc-700/50'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {analytics && (
            <>
              <button
                onClick={handleCopy}
                className="p-1.5 text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 rounded transition-colors"
                title="Copy analytics JSON"
              >
                {copied ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
              </button>
              <button
                onClick={handleDownload}
                className="p-1.5 text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 rounded transition-colors"
                title="Download analytics JSON"
              >
                <Download size={16} />
              </button>
            </>
          )}
          <button
            onClick={loadAnalytics}
            className="p-1.5 text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 rounded transition-colors"
            title="Refresh analytics"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-rose-500/30 bg-rose-500/10 p-3 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 text-rose-400 light:text-rose-800" />
          <span className="text-sm text-rose-300 light:text-rose-800">{error}</span>
        </div>
      )}

      {analytics && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
            <KpiCard
              icon={<Database className="h-5 w-5 text-blue-400" />}
              label="Total CVEs"
              value={analytics.totalCves.toLocaleString()}
              subtitle="In selected range"
            />
            <KpiCard
              icon={<Flame className="h-5 w-5 text-amber-400" />}
              label="CISA KEV"
              value={analytics.kevCount.toLocaleString()}
              subtitle="Known exploited"
            />
            <KpiCard
              icon={<TrendingUp className="h-5 w-5 text-rose-400" />}
              label="Critical + High"
              value={(
                analytics.severityDistribution.critical + analytics.severityDistribution.high
              ).toLocaleString()}
              subtitle="Severe vulnerabilities"
            />
            <KpiCard
              icon={<BarChart3 className="h-5 w-5 text-teal-400" />}
              label="Generated"
              value={formatDate(analytics.generatedAt)}
              subtitle="Data freshness"
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <ChartCard title="CVEs Published Over Time" subtitle="Critical vs High severity">
              <div className="overflow-x-auto">
                <TimelineChart data={analytics.timeline} />
              </div>
            </ChartCard>

            <ChartCard title="Severity Distribution">
              <div className="flex items-center justify-center">
                <PieChart data={severityData} />
              </div>
              <div className="mt-3">
                <Legend items={severityData} />
              </div>
            </ChartCard>

            <ChartCard title="Exploit Status">
              <div className="flex items-center justify-center">
                <PieChart data={exploitData} />
              </div>
              <div className="mt-3">
                <Legend items={exploitData} />
              </div>
            </ChartCard>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <ChartCard
              title="Top Vendors by CVE Count"
              subtitle={`Top ${Math.min(10, analytics.topVendors.length)} vendors`}
            >
              <div className="overflow-x-auto">
                <BarChart
                  data={analytics.topVendors.map((v: VendorAnalytics) => ({
                    label: v.vendor,
                    value: v.cveCount,
                  }))}
                  maxValue={Math.max(...analytics.topVendors.map((v) => v.cveCount), 1)}
                  color="#3b82f6"
                  unit=""
                  showLabels={false}
                />
              </div>
              <div className="mt-2 space-y-1">
                {analytics.topVendors.map((v: VendorAnalytics) => (
                  <div key={v.vendor} className="flex items-center justify-between text-xs">
                    <span className="text-zinc-400 light:text-zinc-600 truncate max-w-[120px]">
                      {v.vendor}
                    </span>
                    <span className="font-mono text-zinc-300 light:text-zinc-800">{v.cveCount}</span>
                  </div>
                ))}
              </div>
            </ChartCard>

            <ChartCard title="CVSS Score Distribution" subtitle="Score bands">
              <div className="overflow-x-auto">
                <HistogramChart bins={analytics.cvssScoreHistogram} />
              </div>
            </ChartCard>
          </div>
        </>
      )}

      {loading && (
        <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 text-blue-400 animate-spin mb-2" />
          <p className="text-sm text-zinc-400 light:text-zinc-600">Loading threat analytics data...</p>
        </div>
      )}

      {!analytics && !loading && !error && (
        <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-8 text-center">
          <BarChart3 className="mx-auto h-10 w-10 text-zinc-600 light:text-zinc-400 mb-3" />
          <p className="text-sm text-zinc-400 light:text-zinc-600">
            Select a timeline range to view threat analytics.
          </p>
        </div>
      )}
    </div>
  );
};

function KpiCard({
  icon,
  label,
  value,
  subtitle,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  subtitle: string;
}) {
  return (
    <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4">
      <div className="flex items-center gap-2 mb-1">{icon}</div>
      <div className="text-2xl font-bold text-zinc-100 light:text-zinc-900">{value}</div>
      <div className="text-sm text-zinc-400 light:text-zinc-600">{label}</div>
      <div className="text-xs text-zinc-500 light:text-zinc-600 mt-0.5">{subtitle}</div>
    </div>
  );
}

function ChartCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4">
      <div className="mb-3">
        <h3 className="text-sm font-medium text-zinc-300 light:text-zinc-800">{title}</h3>
        {subtitle && <p className="text-xs text-zinc-500 light:text-zinc-600">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}
