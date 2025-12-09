function sanitizeValue(value) {
  if (value === undefined) return undefined;
  if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      stack: value.stack,
    };
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item));
  }
  if (typeof value === 'object') {
    const clean = {};
    for (const [key, val] of Object.entries(value)) {
      const sanitized = sanitizeValue(val);
      if (sanitized !== undefined) {
        clean[key] = sanitized;
      }
    }
    return clean;
  }
  return String(value);
}

function normalizeMeta(meta) {
  if (!meta || typeof meta !== 'object') {
    return undefined;
  }
  const clean = sanitizeValue(meta);
  return clean && Object.keys(clean).length > 0 ? clean : undefined;
}

function log(level, scope, message, meta) {
  const payload = {
    level,
    scope,
    message,
    timestamp: new Date().toISOString(),
  };
  const cleanMeta = normalizeMeta(meta);
  if (cleanMeta) {
    payload.meta = cleanMeta;
  }
  const line = JSON.stringify(payload);
  if (level === 'error') {
    console.error(line);
  } else if (level === 'warn') {
    console.warn(line);
  } else {
    console.log(line);
  }
}

function scoped(scope) {
  return {
    info: (message, meta) => log('info', scope, message, meta),
    warn: (message, meta) => log('warn', scope, message, meta),
    error: (message, meta) => log('error', scope, message, meta),
  };
}

module.exports = {
  info: (scope, message, meta) => log('info', scope, message, meta),
  warn: (scope, message, meta) => log('warn', scope, message, meta),
  error: (scope, message, meta) => log('error', scope, message, meta),
  scoped,
};
