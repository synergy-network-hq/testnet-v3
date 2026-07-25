import { modeLabel } from '../../lib/panelViewMode';
import { SNRGButton } from '../../styles/SNRGButton';
import { buildMetricBars } from './controlPanelModel';
import { MODE_SWITCH_ITEMS } from './viewProfiles';
import { jarvisIconSrc } from '../../lib/runtimeAssets';

export function StatusPill({ tone = 'neutral', children, live = false }) {
  return (
    <span className={`cp-status-pill cp-status-pill-${tone} ${live ? 'is-live' : ''}`}>
      {children}
    </span>
  );
}

export function ModeSwitcher({ mode, onChange, compact = false, allowDeveloper = true }) {
  const items = allowDeveloper
    ? MODE_SWITCH_ITEMS
    : MODE_SWITCH_ITEMS.filter((item) => item.id !== 'developer');

  return (
    <div className={`cp-mode-switcher ${compact ? 'is-compact' : ''}`} data-mode-count={items.length}>
      {items.map((item) => (
        <button
          key={item.id}
          type="button"
          className={`cp-mode-button ${mode === item.id ? 'is-active' : ''}`}
          onClick={() => onChange(item.id)}
        >
          <span className="material-icons" aria-hidden="true">{item.icon}</span>
          <span>{item.label}</span>
        </button>
      ))}
    </div>
  );
}

export function SectionHeader({
  eyebrow,
  title,
  copy,
  actions = null,
}) {
  return (
    <header className="cp-section-header">
      <div className="cp-section-copy">
        {eyebrow ? <span className="cp-eyebrow">{eyebrow}</span> : null}
        <h1>{title}</h1>
        {copy ? <p>{copy}</p> : null}
      </div>
      {actions ? <div className="cp-section-actions">{actions}</div> : null}
    </header>
  );
}

export function PanelCard({
  className = '',
  eyebrow,
  title,
  detail,
  action,
  children,
}) {
  return (
    <article className={`cp-panel-card ${className}`.trim()}>
      {(eyebrow || title || detail || action) ? (
        <div className="cp-panel-card-head">
          <div>
            {eyebrow ? <span className="cp-eyebrow">{eyebrow}</span> : null}
            {title ? <h3>{title}</h3> : null}
            {detail ? <p>{detail}</p> : null}
          </div>
          {action ? <div className="cp-panel-card-action">{action}</div> : null}
        </div>
      ) : null}
      {children}
    </article>
  );
}

export function MetricCard({
  label,
  value,
  detail,
  tone = 'cyan',
  icon = 'monitor_heart',
}) {
  return (
    <article className={`cp-metric-card tone-${tone}`}>
      <div className="cp-metric-icon">
        <span className="material-icons" aria-hidden="true">{icon}</span>
      </div>
      <div className="cp-metric-copy">
        <span>{label}</span>
        <strong>{value}</strong>
        {detail ? <small>{detail}</small> : null}
      </div>
    </article>
  );
}

export function JarvisCard({
  title = 'Jarvis insight',
  message,
  mode,
  detailText,
  chips = [],
  footer,
}) {
  return (
    <PanelCard
      className="cp-jarvis-card"
      eyebrow="Jarvis"
      title={title}
      detail={detailText || `${modeLabel(mode)} mode guidance`}
    >
      <div className="cp-jarvis-card-body">
        <div className="cp-jarvis-avatar" aria-hidden="true">
          <img src={jarvisIconSrc} alt="" />
        </div>
        <p>{message}</p>
      </div>
      {chips.length ? (
        <div className="cp-chip-row">
          {chips.map((chip, index) => (
            <span key={`${chip}-${index}`} className="cp-chip">{chip}</span>
          ))}
        </div>
      ) : null}
      {footer ? <div className="cp-panel-inline-note">{footer}</div> : null}
    </PanelCard>
  );
}

export function MetricBars({
  title,
  detail,
  items,
  footer,
}) {
  const normalizedItems = buildMetricBars(items);

  return (
    <PanelCard title={title} detail={detail}>
      <div className="cp-bar-list">
        {normalizedItems.map((item) => (
          <div key={item.id || item.label} className="cp-bar-row">
            <div className="cp-bar-copy">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
            <div className="cp-bar-track">
              <div className={`cp-bar-fill tone-${item.tone || 'cyan'}`} style={{ width: `${item.width}%` }}></div>
            </div>
            {item.detail ? <small>{item.detail}</small> : null}
          </div>
        ))}
      </div>
      {footer ? <div className="cp-panel-inline-note">{footer}</div> : null}
    </PanelCard>
  );
}

export function TopologyMap({
  title,
  detail,
  model,
  action,
}) {
  return (
    <PanelCard title={title} detail={detail} action={action}>
      <div className="cp-topology-map">
        <svg className="cp-topology-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          {model.peers.map((peer) => (
            <line
              key={peer.id}
              x1="50"
              y1="50"
              x2={peer.x}
              y2={peer.y}
              className={`tone-${peer.tone || 'neutral'}`}
            />
          ))}
        </svg>

        <div className="cp-topology-center" style={{ left: '50%', top: '50%' }}>
          <div className="cp-topology-node is-center tone-cyan">
            <span className="material-icons">trip_origin</span>
          </div>
          <div className="cp-topology-label cp-topology-label-center">
            <strong>{model.center.label}</strong>
            <span>{model.center.detail}</span>
            <small>{model.center.metric}</small>
          </div>
        </div>

        {model.peers.map((peer) => (
          <div
            key={peer.id}
            className="cp-topology-peer"
            style={{ left: `${peer.x}%`, top: `${peer.y}%` }}
          >
            <div className={`cp-topology-node tone-${peer.tone || 'neutral'}`}>
              <span className="material-icons">adjust</span>
            </div>
            <div className="cp-topology-label">
              <strong>{peer.label}</strong>
              <span>{peer.status}</span>
              <small>{peer.metric}</small>
            </div>
          </div>
        ))}

        {model.overflowCount > 0 ? (
          <div className="cp-topology-overflow">+{model.overflowCount} more</div>
        ) : null}
      </div>
    </PanelCard>
  );
}

export function ActivityFeed({
  title,
  detail,
  items,
  emptyMessage = 'No recent events yet.',
  fixedLines = 6,
}) {
  return (
    <PanelCard title={title} detail={detail}>
      <div
        className={`cp-activity-feed ${fixedLines ? 'is-scroll-locked' : ''}`}
        style={fixedLines ? { '--cp-feed-lines': fixedLines } : undefined}
      >
        {items.length ? items.map((item) => (
          <article key={item.id} className={`cp-activity-item tone-${item.tone || 'neutral'}`}>
            <div className="cp-activity-marker"></div>
            <div className="cp-activity-copy">
              <div className="cp-activity-head">
                <strong>{item.title}</strong>
                <span>{item.time}</span>
              </div>
              <p>{item.detail}</p>
            </div>
          </article>
        )) : <div className="cp-empty-inline">{emptyMessage}</div>}
      </div>
    </PanelCard>
  );
}

export function EmptyPanel({
  title,
  copy,
  actionLabel,
  onAction,
}) {
  return (
    <div className="cp-empty-panel">
      <span className="material-icons" aria-hidden="true">deployed_code</span>
      <h2>{title}</h2>
      <p>{copy}</p>
      {actionLabel ? (
        <SNRGButton variant="blue" size="sm" onClick={onAction}>
          {actionLabel}
        </SNRGButton>
      ) : null}
    </div>
  );
}
