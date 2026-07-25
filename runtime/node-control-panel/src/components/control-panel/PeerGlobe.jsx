import { useMemo, useRef, useState } from 'react';
import landAtlas from 'world-atlas/land-110m.json';
import { feature } from 'topojson-client';
import { geoGraticule10, geoOrthographic, geoPath } from 'd3-geo';

const LAND_FEATURE = feature(landAtlas, landAtlas.objects.land);
const REGION_COORDINATES = {
  'North America': [-100, 40],
  'South America': [-60, -18],
  Europe: [10, 50],
  Africa: [18, 4],
  'Middle East': [42, 27],
  'Asia Pacific': [118, 20],
  Unmapped: [0, 0],
  Unknown: [0, 0],
};

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

function regionCoordinate(region) {
  return REGION_COORDINATES[region] || REGION_COORDINATES.Unknown;
}

function roleClass(role) {
  if (role === 'bootnode' || role === 'seed') return 'is-hex';
  if (role === 'rpc') return 'is-square';
  if (role === 'observer') return 'is-diamond';
  return 'is-circle';
}

function projectArcPath(from, to) {
  const midX = (from[0] + to[0]) / 2;
  const midY = Math.min(from[1], to[1]) - 12;
  return `M ${from[0]} ${from[1]} Q ${midX} ${midY} ${to[0]} ${to[1]}`;
}

export default function PeerGlobe({
  points = [],
  routes = [],
  regionSummary = [],
  selectedRegion = 'all',
  selectedPeerId = '',
  onSelectRegion = null,
  onSelectPeer = null,
  showRoutes = true,
  mode = 'basic',
}) {
  const svgRef = useRef(null);
  const dragRef = useRef(null);
  const [rotation, setRotation] = useState([-12, -18]);
  const [zoom, setZoom] = useState(1);
  const [hovered, setHovered] = useState(null);

  const projection = useMemo(() => (
    geoOrthographic()
      .translate([210, 210])
      .scale(180 * zoom)
      .clipAngle(90)
      .rotate(rotation)
  ), [rotation, zoom]);

  const landPath = useMemo(() => geoPath(projection)(LAND_FEATURE), [projection]);
  const graticulePath = useMemo(() => geoPath(projection)(geoGraticule10()), [projection]);
  const projectedPoints = useMemo(() => (
    points
      .map((point) => ({
        ...point,
        projected: projection([point.longitude, point.latitude]),
      }))
      .filter((point) => Array.isArray(point.projected))
  ), [points, projection]);
  const projectedRoutes = useMemo(() => (
    routes
      .map((route) => ({
        ...route,
        fromProjected: projection(route.from),
        toProjected: projection(route.to),
      }))
      .filter((route) => Array.isArray(route.fromProjected) && Array.isArray(route.toProjected))
  ), [projection, routes]);
  const projectedRegions = useMemo(() => (
    regionSummary
      .map((region) => ({
        ...region,
        projected: projection(regionCoordinate(region.region)),
      }))
      .filter((region) => Array.isArray(region.projected))
  ), [projection, regionSummary]);

  const handlePointerDown = (event) => {
    dragRef.current = {
      x: event.clientX,
      y: event.clientY,
      rotation,
    };
  };

  const handlePointerMove = (event) => {
    if (!dragRef.current) {
      return;
    }
    const deltaX = event.clientX - dragRef.current.x;
    const deltaY = event.clientY - dragRef.current.y;
    setRotation([
      dragRef.current.rotation[0] - deltaX * 0.35,
      clamp(dragRef.current.rotation[1] + deltaY * 0.22, -70, 70),
    ]);
  };

  const handlePointerUp = () => {
    dragRef.current = null;
  };

  const handleWheel = (event) => {
    event.preventDefault();
    setZoom((current) => clamp(current + (event.deltaY > 0 ? -0.1 : 0.1), 0.85, 2.4));
  };

  return (
    <div className="cp-peer-globe-shell">
      <svg
        ref={svgRef}
        viewBox="0 0 420 420"
        className="cp-peer-globe"
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerLeave={handlePointerUp}
        onWheel={handleWheel}
        role="img"
        aria-label="Peer globe"
      >
        <defs>
          <radialGradient id="cp-globe-fill" cx="50%" cy="50%" r="65%">
            <stop offset="0%" stopColor="rgba(20, 53, 79, 0.88)" />
            <stop offset="100%" stopColor="rgba(4, 16, 27, 0.98)" />
          </radialGradient>
        </defs>
        <circle cx="210" cy="210" r="190" className="cp-peer-globe-sphere" fill="url(#cp-globe-fill)" />
        {graticulePath ? <path d={graticulePath} className="cp-peer-globe-graticule" /> : null}
        {landPath ? <path d={landPath} className="cp-peer-globe-land" /> : null}
        {showRoutes ? projectedRoutes.map((route) => (
          <path
            key={`${route.fromNodeId}-${route.toPeerId}`}
            d={projectArcPath(route.fromProjected, route.toProjected)}
            className={`cp-peer-route tone-${route.healthTone || 'neutral'}`}
          />
        )) : null}
        {projectedRegions.map((region) => (
          <g
            key={region.region}
            className={`cp-peer-region-hotspot ${selectedRegion === region.region ? 'is-active' : ''}`}
            onClick={() => onSelectRegion?.(region.region)}
          >
            <circle
              cx={region.projected[0]}
              cy={region.projected[1]}
              r={Math.max(12, 10 + region.peerCount * 1.1)}
              className={`tone-${region.healthTone || 'neutral'}`}
            />
            <text x={region.projected[0]} y={region.projected[1] - 16}>{region.region}</text>
          </g>
        ))}
        {projectedPoints.map((point) => (
          <g
            key={point.id}
            className={`cp-peer-marker ${roleClass(point.role)} ${selectedPeerId === point.id ? 'is-active' : ''}`}
            transform={`translate(${point.projected[0]}, ${point.projected[1]})`}
            onMouseEnter={() => setHovered(point)}
            onMouseLeave={() => setHovered(null)}
            onClick={() => onSelectPeer?.(point)}
          >
            <circle r={mode === 'basic' ? 3.8 : 4.8} className={`tone-${point.healthTone || 'neutral'}`} />
          </g>
        ))}
      </svg>
      {hovered ? (
        <div className="cp-peer-globe-tooltip">
          <strong>{hovered.label}</strong>
          <span>{hovered.region}</span>
          <small>
            {hovered.latencyMs != null ? `${hovered.latencyMs} ms` : 'Latency pending'}
            {' · '}
            {hovered.health || 'pending'}
          </small>
        </div>
      ) : null}
    </div>
  );
}
