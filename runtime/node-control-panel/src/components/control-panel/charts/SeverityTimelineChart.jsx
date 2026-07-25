import { useMemo } from 'react';
import { PanelCard } from '../ControlPanelShared';
import { buildTicks, formatShortTime, normalizeTimeline } from './chartUtils';

export default function SeverityTimelineChart({
  title = 'Anomaly timeline',
  detail = 'Warnings and errors grouped over time.',
  bins = [],
  selectedId = '',
  onSelect = null,
}) {
  const normalizedBins = useMemo(() => (
    normalizeTimeline(bins, (entry) => (
      Number(entry?.info || 0) + Number(entry?.warn || 0) + Number(entry?.error || 0)
    )).map((entry, index) => ({
      ...entry,
      info: Number(bins[index]?.info || 0),
      warn: Number(bins[index]?.warn || 0),
      error: Number(bins[index]?.error || 0),
    }))
  ), [bins]);
  const ticks = useMemo(() => buildTicks(normalizedBins), [normalizedBins]);
  const maxValue = Math.max(
    1,
    ...normalizedBins.map((entry) => entry.info + entry.warn + entry.error),
  );

  if (!normalizedBins.length) {
    return (
      <PanelCard title={title} detail={detail}>
        <div className="cp-empty-inline">The timeline will populate after log groups accumulate.</div>
      </PanelCard>
    );
  }

  return (
    <PanelCard title={title} detail={detail}>
      <div className="cp-severity-chart">
        <div className="cp-severity-columns">
          {normalizedBins.map((entry) => {
            const total = entry.info + entry.warn + entry.error;
            return (
              <button
                key={entry.id}
                type="button"
                className={`cp-severity-column ${selectedId === entry.id ? 'is-active' : ''}`}
                onClick={() => onSelect?.(entry)}
              >
                <div className="cp-severity-stack">
                  <span
                    className="tone-bad"
                    style={{ height: `${(entry.error / maxValue) * 100}%` }}
                  ></span>
                  <span
                    className="tone-warn"
                    style={{ height: `${(entry.warn / maxValue) * 100}%` }}
                  ></span>
                  <span
                    className="tone-cyan"
                    style={{ height: `${(entry.info / maxValue) * 100}%` }}
                  ></span>
                </div>
                <small>{total}</small>
              </button>
            );
          })}
        </div>
        <div className="cp-chart-footer">
          <div className="cp-chart-legend">
            <span className="cp-chart-legend-item"><span className="cp-chart-dot tone-cyan"></span>Info</span>
            <span className="cp-chart-legend-item"><span className="cp-chart-dot tone-warn"></span>Warnings</span>
            <span className="cp-chart-legend-item"><span className="cp-chart-dot tone-bad"></span>Errors</span>
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
