import { useMemo, useState } from 'react';
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

export default function RewardsTrendChart({
  title = 'Earnings trend',
  detail = 'Rewards history for the selected window.',
  shortWindow = [],
  longWindow = [],
  shortLabel = '7d',
  longLabel = '30d',
}) {
  const [windowKey, setWindowKey] = useState('short');
  const activeSeries = useMemo(
    () => normalizeTimeline(windowKey === 'short' ? shortWindow : longWindow),
    [longWindow, shortWindow, windowKey],
  );
  const bounds = useMemo(() => timelineBounds([activeSeries]), [activeSeries]);
  const scale = useMemo(() => createChartScaler(bounds, WIDTH, HEIGHT), [bounds]);
  const ticks = useMemo(() => buildTicks(activeSeries), [activeSeries]);

  if (!activeSeries.length) {
    return (
      <PanelCard title={title} detail={detail}>
        <div className="cp-empty-inline">Reward points will appear once the fetcher has history to plot.</div>
      </PanelCard>
    );
  }

  return (
    <PanelCard
      title={title}
      detail={detail}
      action={(
        <div className="cp-chip-row">
          <button
            type="button"
            className={`cp-chip cp-chip-button ${windowKey === 'short' ? 'is-active' : ''}`}
            onClick={() => setWindowKey('short')}
          >
            {shortLabel}
          </button>
          <button
            type="button"
            className={`cp-chip cp-chip-button ${windowKey === 'long' ? 'is-active' : ''}`}
            onClick={() => setWindowKey('long')}
          >
            {longLabel}
          </button>
        </div>
      )}
    >
      <div className="cp-chart-shell">
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="cp-chart-svg" role="img" aria-label={title}>
          <defs>
            <linearGradient id="rewards-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="rgba(180, 140, 255, 0.34)" />
              <stop offset="100%" stopColor="rgba(180, 140, 255, 0.05)" />
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
          <path d={buildAreaPath(activeSeries, scale)} fill="url(#rewards-fill)" />
          <path d={buildLinePath(activeSeries, scale)} className="cp-chart-line tone-purple" />
        </svg>
        <div className="cp-chart-footer">
          <div className="cp-chart-legend">
            <span className="cp-chart-legend-item">
              <span className="cp-chart-dot tone-purple"></span>
              {formatRelativeScaleLabel(bounds.maxValue)} max
            </span>
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
