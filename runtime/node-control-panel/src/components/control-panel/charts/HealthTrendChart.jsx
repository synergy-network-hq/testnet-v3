import { useMemo } from 'react';
import { PanelCard } from '../ControlPanelShared';
import {
  buildAreaPath,
  buildLinePath,
  buildTicks,
  createChartScaler,
  formatRelativeScaleLabel,
  formatShortTime,
  normalizeTimeline,
  timelineBounds,
} from './chartUtils';

const WIDTH = 720;
const HEIGHT = 220;

export default function HealthTrendChart({
  title = 'Health trend',
  detail = 'Recent node health and follow-through.',
  data = [],
  tone = 'good',
}) {
  const series = useMemo(() => normalizeTimeline(data), [data]);
  const bounds = useMemo(() => timelineBounds([series]), [series]);
  const scale = useMemo(() => createChartScaler(bounds, WIDTH, HEIGHT), [bounds]);
  const ticks = useMemo(() => buildTicks(series), [series]);

  if (!series.length) {
    return (
      <PanelCard title={title} detail={detail}>
        <div className="cp-empty-inline">Telemetry history will appear after the next refresh window.</div>
      </PanelCard>
    );
  }

  const areaPath = buildAreaPath(series, scale);
  const linePath = buildLinePath(series, scale);

  return (
    <PanelCard title={title} detail={detail}>
      <div className="cp-chart-shell">
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="cp-chart-svg" role="img" aria-label={title}>
          <defs>
            <linearGradient id={`health-fill-${tone}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="rgba(62, 247, 161, 0.34)" />
              <stop offset="100%" stopColor="rgba(62, 247, 161, 0.04)" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75].map((ratio) => (
            <line
              key={ratio}
              x1="16"
              x2={WIDTH - 16}
              y1={16 + (HEIGHT - 32) * ratio}
              y2={16 + (HEIGHT - 32) * ratio}
              className="cp-chart-grid"
            />
          ))}
          <path d={areaPath} fill={`url(#health-fill-${tone})`} />
          <path d={linePath} className={`cp-chart-line tone-${tone}`} />
          {series.map((point) => (
            <circle
              key={point.id}
              cx={scale.x(point.at)}
              cy={scale.y(point.value)}
              r="3.2"
              className={`cp-chart-point tone-${tone}`}
            />
          ))}
        </svg>
        <div className="cp-chart-footer">
          <div className="cp-chart-legend">
            <span className={`cp-chart-dot tone-${tone}`}></span>
            <strong>{formatRelativeScaleLabel(series[series.length - 1]?.value)}</strong>
            <span>Current signal</span>
          </div>
          <div className="cp-chart-ticks">
            {ticks.map((tick) => (
              <span key={tick.id}>{formatShortTime(tick.at)}</span>
            ))}
          </div>
          <div className="cp-chart-scale">
            <span>{formatRelativeScaleLabel(bounds.maxValue)}</span>
            <span>{formatRelativeScaleLabel(bounds.minValue)}</span>
          </div>
        </div>
      </div>
    </PanelCard>
  );
}

