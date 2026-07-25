import JsonInspectorPanel from './JsonInspectorPanel';

export default function LogPayloadInspector({
  entry = null,
}) {
  if (!entry) {
    return <div className="cp-empty-inline">Select a log entry to inspect its raw payload.</div>;
  }

  return (
    <JsonInspectorPanel
      title="Event payload"
      value={entry.metadata || entry}
      emptyMessage="No payload is attached to the selected log event."
    />
  );
}

