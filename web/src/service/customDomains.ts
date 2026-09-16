export interface CustomDomainsResponse {
  domains: string[];
  message?: string;
}

export async function fetchCustomDomains(): Promise<string[]> {
  const response = await fetch("/api/blocklist/custom");
  if (!response.ok) {
    throw new Error("Failed to fetch custom domains");
  }
  const data: CustomDomainsResponse = await response.json();
  return data.domains ?? [];
}

export async function addCustomDomains(domains: string[]): Promise<CustomDomainsResponse> {
  const response = await fetch("/api/blocklist/custom", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domains }),
  });
  if (!response.ok) {
    throw new Error("Failed to add custom domains");
  }
  const data: CustomDomainsResponse = await response.json();
  return data;
}

export async function removeCustomDomains(domains: string[]): Promise<CustomDomainsResponse> {
  const response = await fetch("/api/blocklist/custom", {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domains }),
  });
  if (!response.ok) {
    throw new Error("Failed to remove custom domains");
  }
  const data: CustomDomainsResponse = await response.json();
  return data;
}
