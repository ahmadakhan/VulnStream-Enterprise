/** Build a short, human-friendly display name for a pipeline execution from its id.
 *
 * Executions are keyed by an opaque UUID, but the Execution history list renders a
 * readable label (e.g. `Run 3add6860`) instead of the raw identifier. Legacy rows
 * stored before this name was persisted fall back to this helper on read. */
export const formatExecutionName = (id: string): string => `Run ${id.slice(0, 8)}`;
