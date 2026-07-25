export default function PeerGlobeLegend() {
  return (
    <div className="cp-peer-globe-legend">
      <span className="cp-chart-legend-item"><span className="cp-chart-dot tone-good"></span>Healthy</span>
      <span className="cp-chart-legend-item"><span className="cp-chart-dot tone-warn"></span>Degraded</span>
      <span className="cp-chart-legend-item"><span className="cp-chart-dot tone-bad"></span>Offline or stale</span>
      <span className="cp-chart-legend-item"><span className="cp-chart-dot tone-purple"></span>Pending</span>
    </div>
  );
}

