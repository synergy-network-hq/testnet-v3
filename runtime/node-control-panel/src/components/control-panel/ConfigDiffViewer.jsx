function compareLines(leftText, rightText) {
  const leftLines = String(leftText || '').split('\n');
  const rightLines = String(rightText || '').split('\n');
  const maxLength = Math.max(leftLines.length, rightLines.length);

  return Array.from({ length: maxLength }, (_, index) => {
    const left = leftLines[index] ?? '';
    const right = rightLines[index] ?? '';
    let tone = 'neutral';
    if (left && !right) tone = 'bad';
    if (!left && right) tone = 'good';
    if (left && right && left !== right) tone = 'warn';
    return {
      id: `diff-${index}`,
      line: index + 1,
      left,
      right,
      tone,
    };
  });
}

export default function ConfigDiffViewer({
  leftTitle = 'Current config',
  rightTitle = 'Expected profile',
  leftText = '',
  rightText = '',
}) {
  const rows = compareLines(leftText, rightText);

  return (
    <div className="cp-config-diff">
      <div className="cp-config-diff-head">
        <strong>{leftTitle}</strong>
        <strong>{rightTitle}</strong>
      </div>
      <div className="cp-config-diff-body">
        {rows.map((row) => (
          <div key={row.id} className={`cp-config-diff-row tone-${row.tone}`}>
            <span className="cp-config-diff-line">{row.line}</span>
            <pre>{row.left || ' '}</pre>
            <pre>{row.right || ' '}</pre>
          </div>
        ))}
      </div>
    </div>
  );
}
