export default function JsonInspectorPanel({
  title = 'JSON inspector',
  value = null,
  emptyMessage = 'Nothing selected yet.',
}) {
  if (value == null) {
    return <div className="cp-empty-inline">{emptyMessage}</div>;
  }

  return (
    <div className="cp-json-inspector">
      <div className="cp-json-inspector-head">
        <strong>{title}</strong>
      </div>
      <pre className="cp-json-block">{JSON.stringify(value, null, 2)}</pre>
    </div>
  );
}

