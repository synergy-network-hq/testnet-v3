import { useMemo } from 'react';
import { PanelCard } from '../ControlPanelShared';
import {
  buildLinePath,
  buildTicks,
  createChartScaler,
  formatShortTime,
  normalizeTimeline,
  timelineBounds,
} from './chartUtils';

const WIDTH = 720;
const HEIGHT = 220;

function buildSeries(data = []) {
  const safeData = Array.isArray(data) ? data : [];
  return [
    {
      key: 'cpu',
      label: 'CPU',
      tone: 'cyan',
      values: normalizeTimeline(safeData, (entry) => entry?.cpuPercent ?? 0),
    },
    {
      key: 'memory',
      label: 'Memory',
      tone: 'purple',
      values: normalizeTimeline(safeData, (entry) => entry?.memoryMb ?? 0),
    },
    {
      key: 'disk',
      label: 'Disk',
      tone: 'warn',
      values: normalizeTimeline(safeData, (entry) => entry?.diskPercent ?? 0),
    },
  ].filter((entry) => entry.values.length);
}

export default function ResourceTrendChart({
  title = 'Machine diagnostics',
  detail = 'CPU, memory, and disk pressure for this runtime.',
  data = [],
}) {
  const series = useMemo(() => buildSeries(data), [data]);
  const bounds = useMemo(() => timelineBounds(series.map((entry) => entry.values)), [series]);
  const scale = useMemo(() => createChartScaler(bounds, WIDTH, HEIGHT), [bounds]);
  const ticks = useMemo(() => buildTicks(series[0]?.values || []), [series]);

  if (!series.length) {
    return (
      <PanelCard title={title} detail={detail}>
        <div className="cp-empty-inline">Resource traces have not been captured by the current runtime yet.</div>
      </PanelCard>
    );
  }

  return (
    <PanelCard title={title} detail={detail}>
      <div className="cp-chart-shell">
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="cp-chart-svg" role="img" aria-label={title}>
          {[0.2, 0.4, 0.6, 0.8].map((ratio) => (
            <line
              key={ratio}
              x1="16"
              x2={WIDTH - 16}
              y1={16 + (HEIGHT - 32) * ratio}
              y2={16 + (HEIGHT - 32) * ratio}
              className="cp-chart-grid"
            />
          ))}
          {series.map((entry) => (
            <path
              key={entry.key}
              d={buildLinePath(entry.values, scale)}
              className={`cp-chart-line tone-${entry.tone}`}
            />
          ))}
        </svg>
        <div className="cp-chart-footer">
          <div className="cp-chart-legend cp-chart-legend-wrap">
            {series.map((entry) => (
              <span key={entry.key} className="cp-chart-legend-item">
                <span className={`cp-chart-dot tone-${entry.tone}`}></span>
                {entry.label}
              </span>
            ))}
          </div>
          <div className="cp-chart-ticks">
            {ticks.map((tick) => (
              <span key={tick.id}>{formatShortTime(tick.at)}</span>
            ))}
          </div>
        </div>
      </div>
    </PanelCard>
  );
}
