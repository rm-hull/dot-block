export interface User {
  user: string;
  email: string;
  emailHash: string;
}

async function sha256(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function fetchWhoAmI(): Promise<User> {
  const response = await fetch("/api/whoami");
  if (!response.ok) {
    throw new Error("Failed to fetch user info");
  }
  const data = await response.json();
  const emailHash = await sha256(data.email.trim().toLowerCase());
  return { ...data, emailHash };
}
