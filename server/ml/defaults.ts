/**
 * Default constants for ML-powered pipeline integration.
 *
 * These mirror the existing hardcoded defaults in the pipeline code so that
 * the ML integration layer is a strict superset of behavior — when models
 * are untrained, the system behaves identically to the pre-ML baseline.
 */

/** Default auto-dispatch confidence threshold (percentage) — matches pipelineEngine.ts. */
export const DEFAULT_AUTO_DISPATCH_THRESHOLD = 90;

/** Default initial retry delay in minutes for email delivery. */
export const DEFAULT_EMAIL_RETRY_INITIAL_DELAY_MINUTES = 5;

/** Default backoff multiplier for email delivery. */
export const DEFAULT_EMAIL_RETRY_MULTIPLIER = 2;

/** Default maximum delay in minutes (1 week) for email delivery. */
export const DEFAULT_EMAIL_RETRY_MAX_DELAY_MINUTES = 1440;

/** Default maximum delivery attempts. */
export const DEFAULT_EMAIL_RETRY_MAX_ATTEMPTS = 5;
