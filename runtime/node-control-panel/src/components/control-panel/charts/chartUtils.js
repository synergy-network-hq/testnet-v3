export function normalizeTimeline(data = [], selector = (entry) => entry?.value ?? 0) {
  const safeData = Array.isArray(data) ? data : [];
  return safeData
    .map((entry, index) => ({
      id: entry?.id || `point-${index}`,
      at: Number(entry?.at ?? Date.now()),
      value: Number(selector(entry)) || 0,
      label: entry?.label || '',
      raw: entry,
    }))
    .sort((left, right) => left.at - right.at);
}

export function timelineBounds(seriesList = []) {
  const allSeries = seriesList.flat();
  const values = allSeries.map((entry) => Number(entry?.value) || 0);
  const atValues = allSeries.map((entry) => Number(entry?.at) || 0);
  return {
    minValue: values.length ? Math.min(...values) : 0,
    maxValue: values.length ? Math.max(...values, 1) : 1,
    minAt: atValues.length ? Math.min(...atValues) : Date.now(),
    maxAt: atValues.length ? Math.max(...atValues) : Date.now() + 1,
  };
}

export function createChartScaler(bounds, width, height, padding = 16) {
  const minX = bounds.minAt;
  const maxX = bounds.maxAt === bounds.minAt ? bounds.maxAt + 1 : bounds.maxAt;
  const minY = Math.min(0, bounds.minValue);
  const maxY = bounds.maxValue === minY ? minY + 1 : bounds.maxValue;

  return {
    x(value) {
      const ratio = (value - minX) / (maxX - minX);
      return padding + ratio * (width - padding * 2);
    },
    y(value) {
      const ratio = (value - minY) / (maxY - minY);
      return height - padding - ratio * (height - padding * 2);
    },
    baseline: height - padding,
    bounds: { minX, maxX, minY, maxY },
  };
}

export function buildLinePath(points, scale) {
  if (!points.length) {
    return '';
  }

  return points
    .map((entry, index) => `${index === 0 ? 'M' : 'L'} ${scale.x(entry.at).toFixed(2)} ${scale.y(entry.value).toFixed(2)}`)
    .join(' ');
}

export function buildAreaPath(points, scale) {
  if (!points.length) {
    return '';
  }

  const firstX = scale.x(points[0].at);
  const lastX = scale.x(points[points.length - 1].at);
  const line = buildLinePath(points, scale);
  return `${line} L ${lastX.toFixed(2)} ${scale.baseline.toFixed(2)} L ${firstX.toFixed(2)} ${scale.baseline.toFixed(2)} Z`;
}

export function buildTicks(points = [], count = 4) {
  if (!points.length) {
    return [];
  }
  if (points.length <= count) {
    return points;
  }

  const ticks = [];
  const lastIndex = points.length - 1;
  for (let index = 0; index < count; index += 1) {
    const pointIndex = Math.round((lastIndex * index) / Math.max(count - 1, 1));
    ticks.push(points[pointIndex]);
  }
  return ticks;
}

export function formatShortTime(value) {
  return new Date(value).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatRelativeScaleLabel(value) {
  const numeric = Number(value) || 0;
  if (numeric >= 1000) {
    return `${Math.round(numeric / 100) / 10}k`;
  }
  return `${Math.round(numeric)}`;
}

