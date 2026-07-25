export default function TerminalTabs({
  tabs = [],
  activeTabId = '',
  onChange = null,
}) {
  return (
    <div className="cp-terminal-tabs" role="tablist" aria-label="Developer dock tabs">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={activeTabId === tab.id}
          className={`cp-terminal-tab ${activeTabId === tab.id ? 'is-active' : ''}`}
          onClick={() => onChange?.(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

