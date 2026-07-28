/**
 * Shared chart engine for the Synergy Node Control Panel.
 *
 * Pure geometry, scale and formatting helpers plus a few small React hooks.
 * Everything renders as plain SVG - no third-party charting dependency, so the
 * Electron bundle stays lean and the terminal theme stays authoritative.
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';

/* ------------------------------------------------------------------ *
 * Numbers
 * ------------------------------------------------------------------ */

export function finiteNumber(value) {
  if (value == null || value === '') return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function fixed(value) {
  return Number.isFinite(value) ? value.toFixed(2) : '0';
}

function roundToStep(value, step) {
  const decimals = step < 1 ? Math.min(6, Math.ceil(-Math.log10(step)) + 1) : 0;
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}

/**
 * Build a "nice" axis domain: round bounds and evenly spaced ticks that land on
 * human-readable values (1 / 2 / 5 x 10^n) instead of arbitrary fractions.
 */
export function niceScale(minValue, maxValue, targetTicks = 5, options = {}) {
  const { zeroBaseline = false, padRatio = 0.08, integerSteps = false } = options;
  let min = finiteNumber(minValue) ?? 0;
  let max = finiteNumber(maxValue) ?? 1;

  if (min > max) {
    const swap = min;
    min = max;
    max = swap;
  }

  // Telemetry that is physically non-negative (peer counts, latency, sync gap)
  // must never render a negative axis floor just because of domain padding.
  const nonNegativeSeries = min >= 0;

  if (min === max) {
    const pad = Math.abs(min) > 0 ? Math.abs(min) * 0.12 : 1;
    min -= pad;
    max += pad;
  } else if (padRatio > 0) {
    const pad = (max - min) * padRatio;
    min -= pad;
    max += pad;
  }

  if (zeroBaseline || (min > 0 && min < (max - min) * 0.45)) {
    min = Math.min(0, min);
  }

  const span = max - min || 1;
  const rawStep = span / Math.max(1, targetTicks - 1);
  const magnitude = 10 ** Math.floor(Math.log10(Math.abs(rawStep) || 1));
  const residual = rawStep / magnitude;
  const stepMultiplier = residual > 5 ? 10 : residual > 2 ? 5 : residual > 1 ? 2 : 1;
  // Discrete metrics (peer counts, block gaps) must not produce fractional
  // gridlines - a "12.5 peers" tick is not a real quantity.
  const step = integerSteps
    ? Math.max(1, Math.round(stepMultiplier * magnitude))
    : stepMultiplier * magnitude;

  let niceMin = Math.floor(min / step) * step;
  const niceMax = Math.ceil(max / step) * step;
  if (nonNegativeSeries && niceMin < 0) niceMin = 0;
  const tickCount = Math.max(1, Math.round((niceMax - niceMin) / step));

  const ticks = [];
  for (let index = 0; index <= tickCount; index += 1) {
    ticks.push(roundToStep(niceMin + index * step, step));
  }

  return { min: niceMin, max: niceMax || 1, step, ticks };
}

/** Compact axis notation: 1.2k, 3.4M, 0.85 */
export function formatCompactNumber(value) {
  const numeric = finiteNumber(value);
  if (numeric == null) return '--';
  const magnitude = Math.abs(numeric);
  if (magnitude >= 1e9) return `${trimZeros(numeric / 1e9)}B`;
  if (magnitude >= 1e6) return `${trimZeros(numeric / 1e6)}M`;
  if (magnitude >= 1e4) return `${trimZeros(numeric / 1e3)}k`;
  if (magnitude >= 1000) return numeric.toLocaleString(undefined, { maximumFractionDigits: 0 });
  if (magnitude >= 10) return `${Math.round(numeric * 10) / 10}`;
  if (magnitude === 0) return '0';
  if (magnitude < 0.01) return numeric.toExponential(1);
  return `${Math.round(numeric * 100) / 100}`;
}

function trimZeros(value) {
  const rounded = Math.round(value * 10) / 10;
  return Number.isInteger(rounded) ? `${rounded}` : rounded.toFixed(1);
}

/**
 * Build an axis label formatter for a specific domain.
 *
 * Prefers the caller's own formatter when its output is short and unambiguous.
 * Otherwise falls back to compact notation carrying just enough decimal places
 * that adjacent ticks stay distinguishable - without this, a block-height axis
 * spanning 1,284,000-1,288,000 renders every tick as "1.3M".
 */
export function axisLabelFormatter(domain, formatValue = (value) => `${value}`) {
  const { ticks = [], step = 1 } = domain || {};
  if (!ticks.length) return (value) => String(formatValue(value));

  const direct = ticks.map((tick) => String(formatValue(tick)));
  const readable = direct.every((label) => label.length <= 8);
  const distinct = new Set(direct).size === direct.length;
  if (readable && distinct) {
    const lookup = new Map(ticks.map((tick, index) => [tick, direct[index]]));
    return (value) => lookup.get(value) ?? String(formatValue(value));
  }

  const magnitude = Math.max(...ticks.map((tick) => Math.abs(tick)), 0);
  const [suffix, divisor] = magnitude >= 1e9
    ? ['B', 1e9]
    : magnitude >= 1e6
      ? ['M', 1e6]
      : magnitude >= 1e3
        ? ['k', 1e3]
        : ['', 1];
  const decimals = Math.min(4, Math.max(0, Math.ceil(Math.log10(divisor / Math.abs(step || 1)))));
  return (value) => `${(value / divisor).toFixed(decimals)}${suffix}`;
}

/** Percentage delta between the first and last sample of a series. */
export function seriesDelta(values = []) {
  const clean = values.filter((value) => finiteNumber(value) != null);
  if (clean.length < 2) return null;
  const first = Number(clean[0]);
  const last = Number(clean[clean.length - 1]);
  const absolute = last - first;
  if (first === 0) return { absolute, percent: null, direction: directionOf(absolute) };
  return {
    absolute,
    percent: (absolute / Math.abs(first)) * 100,
    direction: directionOf(absolute),
  };
}

function directionOf(value) {
  if (Math.abs(value) < 1e-9) return 'flat';
  return value > 0 ? 'up' : 'down';
}

/** min / max / average / last, ignoring null gaps. */
export function seriesStats(values = []) {
  const clean = values.map(finiteNumber).filter((value) => value != null);
  if (!clean.length) return null;
  let min = clean[0];
  let max = clean[0];
  let total = 0;
  clean.forEach((value) => {
    if (value < min) min = value;
    if (value > max) max = value;
    total += value;
  });
  return { min, max, average: total / clean.length, last: clean[clean.length - 1], count: clean.length };
}

/* ------------------------------------------------------------------ *
 * Path geometry
 * ------------------------------------------------------------------ */

/**
 * Monotone cubic interpolation (Fritsch-Carlson). Produces a smooth curve that
 * never overshoots the data - critical for telemetry, where a pretty-but-wrong
 * spline can imply a spike that never happened.
 */
export function monotonePath(points = []) {
  const count = points.length;
  if (!count) return '';
  if (count === 1) return `M ${fixed(points[0].x)} ${fixed(points[0].y)}`;
  if (count === 2) {
    return `M ${fixed(points[0].x)} ${fixed(points[0].y)} L ${fixed(points[1].x)} ${fixed(points[1].y)}`;
  }

  const dxs = [];
  const slopes = [];
  for (let index = 0; index < count - 1; index += 1) {
    const dx = points[index + 1].x - points[index].x;
    const dy = points[index + 1].y - points[index].y;
    dxs.push(dx);
    slopes.push(dx === 0 ? 0 : dy / dx);
  }

  const tangents = [slopes[0]];
  for (let index = 0; index < dxs.length - 1; index += 1) {
    const slope = slopes[index];
    const nextSlope = slopes[index + 1];
    if (slope * nextSlope <= 0) {
      tangents.push(0);
    } else {
      const dx = dxs[index];
      const nextDx = dxs[index + 1];
      const common = dx + nextDx;
      tangents.push((3 * common) / ((common + nextDx) / slope + (common + dx) / nextSlope));
    }
  }
  tangents.push(slopes[slopes.length - 1]);

  let path = `M ${fixed(points[0].x)} ${fixed(points[0].y)}`;
  for (let index = 0; index < dxs.length; index += 1) {
    const start = points[index];
    const end = points[index + 1];
    const dx = dxs[index] / 3;
    path += ` C ${fixed(start.x + dx)} ${fixed(start.y + tangents[index] * dx)}`
      + ` ${fixed(end.x - dx)} ${fixed(end.y - tangents[index + 1] * dx)}`
      + ` ${fixed(end.x)} ${fixed(end.y)}`;
  }
  return path;
}

export function polylinePath(points = []) {
  if (!points.length) return '';
  return points
    .map((point, index) => `${index === 0 ? 'M' : 'L'} ${fixed(point.x)} ${fixed(point.y)}`)
    .join(' ');
}

export function linePathFor(points, smooth = true) {
  return smooth ? monotonePath(points) : polylinePath(points);
}

/** Close a line path down to a baseline so it can be filled as an area. */
export function areaPathFrom(linePath, points, baselineY) {
  if (!linePath || !points.length) return '';
  const first = points[0];
  const last = points[points.length - 1];
  return `${linePath} L ${fixed(last.x)} ${fixed(baselineY)} L ${fixed(first.x)} ${fixed(baselineY)} Z`;
}

/**
 * Split a coordinate list on null entries so missing telemetry renders as a real
 * gap in the line rather than a straight lie between two distant samples.
 */
export function segmentCoordinates(coordinates = []) {
  const segments = [];
  let current = [];
  coordinates.forEach((coordinate) => {
    if (coordinate) {
      current.push(coordinate);
    } else if (current.length) {
      segments.push(current);
      current = [];
    }
  });
  if (current.length) segments.push(current);
  return segments;
}

/* ------------------------------------------------------------------ *
 * Arc geometry (gauges / donuts)
 * ------------------------------------------------------------------ */

export function polarPoint(cx, cy, radius, angleDegrees) {
  const radians = ((angleDegrees - 90) * Math.PI) / 180;
  return { x: cx + radius * Math.cos(radians), y: cy + radius * Math.sin(radians) };
}

export function arcPath(cx, cy, radius, startAngle, endAngle) {
  const start = polarPoint(cx, cy, radius, endAngle);
  const end = polarPoint(cx, cy, radius, startAngle);
  const largeArc = endAngle - startAngle <= 180 ? '0' : '1';
  return `M ${fixed(start.x)} ${fixed(start.y)} A ${radius} ${radius} 0 ${largeArc} 0 ${fixed(end.x)} ${fixed(end.y)}`;
}

/* ------------------------------------------------------------------ *
 * Hooks
 * ------------------------------------------------------------------ */

/** Observe an element's rendered size so charts can draw at true pixel scale. */
export function useElementSize(defaultWidth = 480, defaultHeight = 200) {
  const ref = useRef(null);
  const [size, setSize] = useState({ width: defaultWidth, height: defaultHeight });

  useLayoutEffect(() => {
    const element = ref.current;
    if (!element || typeof ResizeObserver === 'undefined') return undefined;

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      const box = entry.contentRect;
      setSize((previous) => {
        const width = Math.round(box.width);
        const height = Math.round(box.height);
        if (previous.width === width && previous.height === height) return previous;
        return { width: width || defaultWidth, height: height || defaultHeight };
      });
    });

    observer.observe(element);
    return () => observer.disconnect();
  }, [defaultWidth, defaultHeight]);

  return [ref, size];
}

/**
 * Track the pointer across a plot area and report the nearest sample index.
 * Returns handlers to spread onto the interactive <svg>.
 */
export function usePointerIndex(coordinates, { left = 0, right = 0 } = {}) {
  const [activeIndex, setActiveIndex] = useState(null);
  const surfaceRef = useRef(null);

  const handleMove = useCallback((event) => {
    const surface = surfaceRef.current;
    if (!surface || !coordinates.length) return;
    const rect = surface.getBoundingClientRect();
    if (!rect.width) return;
    const ratio = (event.clientX - rect.left) / rect.width;
    const viewX = ratio * (surface.viewBox?.baseVal?.width || rect.width);

    let nearest = null;
    let nearestDistance = Infinity;
    coordinates.forEach((coordinate, index) => {
      if (!coordinate) return;
      const distance = Math.abs(coordinate.x - viewX);
      if (distance < nearestDistance) {
        nearestDistance = distance;
        nearest = index;
      }
    });
    setActiveIndex(nearest);
  }, [coordinates]);

  const handleLeave = useCallback(() => setActiveIndex(null), []);

  useEffect(() => {
    setActiveIndex(null);
  }, [coordinates.length]);

  return {
    activeIndex,
    surfaceRef,
    surfaceProps: {
      onPointerMove: handleMove,
      onPointerLeave: handleLeave,
      onPointerCancel: handleLeave,
    },
    // guard against the left/right plot padding being unused by consumers
    plotInset: { left, right },
  };
}

/** One-shot mount flag used to trigger the draw-in animation. */
export function useMountedFlag(delay = 40) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const timer = window.setTimeout(() => setMounted(true), delay);
    return () => window.clearTimeout(timer);
  }, [delay]);
  return mounted;
}

/* ------------------------------------------------------------------ *
 * Time axis
 * ------------------------------------------------------------------ */

/** Pick evenly distributed indices for time-axis labels without crowding. */
export function axisTickIndices(length, maxTicks = 5) {
  if (length <= 0) return [];
  if (length <= maxTicks) return Array.from({ length }, (unused, index) => index);
  const lastIndex = length - 1;
  const indices = [];
  for (let index = 0; index < maxTicks; index += 1) {
    indices.push(Math.round((lastIndex * index) / (maxTicks - 1)));
  }
  return [...new Set(indices)];
}

export function normalizeTimestamp(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;
  // Seconds-since-epoch values arrive from the control service; scale to ms.
  return numeric > 0 && numeric < 1e12 ? numeric * 1000 : numeric;
}
