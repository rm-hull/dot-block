export interface BlocklistStatus {
  message?: string;
  errors?: string[];
  blocklists?: Blocklist[];
}

export interface Blocklist {
  name: string;
  title?: string;
  description?: string;
  url: string;
  schedule: string;
  size: number;
  last_fetched?: Date;
  last_updated?: Date;
  error?: string;
  metadata?: Record<string, string>;
  estimated_false_positive_rate?: number;
  disabled_until?: Date;
}

export type Action = "reload" | "disable" | "reenable";

export async function fetchBlocklists(): Promise<BlocklistStatus> {
  const response = await fetch("/api/blocklist/status");
  if (!response.ok) {
    throw new Error("Failed to fetch blocklist status");
  }
  return await response.json();
}

export async function blocklistAction(
  action: Action,
  name: string,
  payload?: Record<string, unknown>
): Promise<BlocklistStatus> {
  const response = await fetch(`/api/blocklist/${action}`, {
    method: "POST",
    body: JSON.stringify({ ...payload, name }),
  });
  if (!response.ok) {
    throw new Error(`Failed to ${action} blocklist`);
  }
  return await response.json();
}
