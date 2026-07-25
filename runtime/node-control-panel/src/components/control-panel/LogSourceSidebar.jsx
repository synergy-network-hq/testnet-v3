export default function LogSourceSidebar({
  sources = [],
  selectedSourceId = '',
  onSelectSource = null,
}) {
  if (!sources.length) {
    return <div className="cp-empty-inline">Source files will appear after the next log refresh.</div>;
  }

  return (
    <div className="cp-source-list">
      {sources.map((source) => (
        <button
          key={source.id}
          type="button"
          className={`cp-source-item cp-source-button ${selectedSourceId === source.id ? 'is-active' : ''}`}
          onClick={() => onSelectSource?.(source)}
        >
          <div>
            <strong>{source.label}</strong>
            <span>{source.path || 'Source path not reported'}</span>
          </div>
          <small>{source.available ? `${source.line_count || 0} lines` : 'Not reported'}</small>
        </button>
      ))}
    </div>
  );
}
