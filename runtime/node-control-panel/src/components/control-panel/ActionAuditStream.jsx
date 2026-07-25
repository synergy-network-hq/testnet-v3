import { formatTimestamp } from './controlPanelModel';

export default function ActionAuditStream({
  entries = [],
  emptyMessage = 'No actions recorded yet.',
}) {
  if (!entries.length) {
    return <div className="cp-empty-inline">{emptyMessage}</div>;
  }

  return (
    <div className="cp-action-audit">
      {entries.map((entry) => (
        <article key={entry.id} className={`cp-action-audit-item tone-${entry.status || 'neutral'}`}>
          <div className="cp-action-audit-head">
            <strong>{entry.title}</strong>
            <span>{formatTimestamp(entry.at)}</span>
          </div>
          {entry.detail ? <p>{entry.detail}</p> : null}
          <div className="cp-action-audit-meta">
            <small>{entry.source || 'control-panel'}</small>
            {entry.code ? <small>{entry.code}</small> : null}
            {entry.command ? <code>{entry.command}</code> : null}
          </div>
        </article>
      ))}
    </div>
  );
}

