const iso8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export function dateReviver(_key: string, value: unknown) {
  return typeof value === "string" && iso8601.test(value) ? new Date(value) : value;
}