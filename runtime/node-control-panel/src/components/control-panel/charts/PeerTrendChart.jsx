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
const HEIGHT = 240;

function normalizeSeries(series = []) {
  return (Array.isArray(series) ? series : [])
    .filter((entry) => Array.isArray(entry?.values) && entry.values.length)
    .map((entry) => ({
      ...entry,
      values: normalizeTimeline(entry.values),
    }));
}

export default function PeerTrendChart({
  title = 'Operational trend panel',
  detail = 'Peer count, sync lag, and runtime posture over time.',
  series = [],
}) {
  const normalizedSeries = useMemo(() => normalizeSeries(series), [series]);
  const bounds = useMemo(
    () => timelineBounds(normalizedSeries.map((entry) => entry.values)),
    [normalizedSeries],
  );
  const scale = useMemo(() => createChartScaler(bounds, WIDTH, HEIGHT), [bounds]);
  const ticks = useMemo(
    () => buildTicks(normalizedSeries[0]?.values || []),
    [normalizedSeries],
  );

  if (!normalizedSeries.length) {
    return (
      <PanelCard title={title} detail={detail}>
        <div className="cp-empty-inline">Trend lines need at least a few live points before they can render.</div>
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
          {normalizedSeries.map((entry) => (
            <path
              key={entry.key || entry.label}
              d={buildLinePath(entry.values, scale)}
              className={`cp-chart-line tone-${entry.tone || 'cyan'}`}
            />
          ))}
        </svg>
        <div className="cp-chart-footer">
          <div className="cp-chart-legend cp-chart-legend-wrap">
            {normalizedSeries.map((entry) => (
              <span key={entry.key || entry.label} className="cp-chart-legend-item">
                <span className={`cp-chart-dot tone-${entry.tone || 'cyan'}`}></span>
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
