export interface User {
  user: string;
  email: string;
  emailHash: string;
  api_key: string;
}

async function sha256(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

let globalApiKey: string | null = null;
const BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

export function setApiKey(key: string) {
  globalApiKey = key;
}

export function getApiKey(): string | null {
  return globalApiKey;
}

export async function fetchWithAuth(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (globalApiKey) {
    headers.set("X-API-Key", globalApiKey);
  }
  return await fetch(BASE_URL + input, { ...init, headers });
}

export async function fetchWhoAmI(): Promise<User> {
  const response = await fetch("/whoami");
  if (!response.ok) {
    throw new Error("Failed to fetch user info");
  }
  const data = await response.json();
  const emailHash = await sha256(data.email.trim().toLowerCase());
  if (data.api_key) {
    setApiKey(data.api_key);
  }
  return { ...data, emailHash };
}
