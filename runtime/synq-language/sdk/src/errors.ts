export class UnsupportedBackendError extends Error {
  constructor(feature: string) {
    super(
      `${feature} requires a PQC backend. Restore aegis-pqsynq/pqsynq or wire a supported SynQ PQC provider before using this SDK API.`
    );
    this.name = 'UnsupportedBackendError';
  }
}

export function unsupportedBackend(feature: string): never {
  throw new UnsupportedBackendError(feature);
}
