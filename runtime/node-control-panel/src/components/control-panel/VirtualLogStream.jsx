import { useEffect, useMemo, useRef, useState } from 'react';

const ROW_HEIGHT = 34;
const OVERSCAN = 8;

export default function VirtualLogStream({
  entries = [],
  selectedEntryId = '',
  onSelectEntry = null,
  autoScroll = false,
}) {
  const containerRef = useRef(null);
  const [scrollTop, setScrollTop] = useState(0);
  const totalHeight = entries.length * ROW_HEIGHT;

  useEffect(() => {
    if (!containerRef.current) {
      return undefined;
    }

    const handleScroll = () => {
      setScrollTop(containerRef.current.scrollTop);
    };

    const element = containerRef.current;
    element.addEventListener('scroll', handleScroll, { passive: true });
    return () => {
      element.removeEventListener('scroll', handleScroll);
    };
  }, []);

  const viewportHeight = containerRef.current?.clientHeight || 440;
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIndex = Math.min(
    entries.length,
    startIndex + Math.ceil(viewportHeight / ROW_HEIGHT) + OVERSCAN * 2,
  );

  const visibleEntries = useMemo(
    () => entries.slice(startIndex, endIndex),
    [endIndex, entries, startIndex],
  );

  useEffect(() => {
    if (!autoScroll || !containerRef.current) {
      return;
    }
    containerRef.current.scrollTop = containerRef.current.scrollHeight;
  }, [autoScroll, entries.length]);

  if (!entries.length) {
    return <div className="cp-empty-inline">The live stream is empty right now.</div>;
  }

  return (
    <div ref={containerRef} className="cp-virtual-log-stream">
      <div style={{ height: `${totalHeight}px`, position: 'relative' }}>
        <div style={{ transform: `translateY(${startIndex * ROW_HEIGHT}px)` }}>
          {visibleEntries.map((entry) => (
            <button
              key={entry.id}
              type="button"
              className={`cp-virtual-log-row ${selectedEntryId === entry.id ? 'is-active' : ''}`}
              onClick={() => onSelectEntry?.(entry)}
            >
              <span className={`cp-log-badge tone-${entry.tone || 'neutral'}`}>{entry.level || 'INFO'}</span>
              <strong>{entry.sourceLabel || entry.module || 'node'}</strong>
              <span>{entry.time}</span>
              <p>{entry.raw || entry.detail}</p>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
