import type { DomainAssessment } from "@/types/net-intent/domain-analysis";
import type { UrlScanResult } from "@/types/net-intent/url-scan";

const BASE_URL = "https://api.hz-nbg1.destructuring-bind.org/v1/net-intent";

export async function fetchDomainAnalysis(fqdn: string): Promise<DomainAssessment> {
  const response = await fetch(`${BASE_URL}/analyze?domain=${fqdn}`);
  if (!response.ok) {
    throw new Error("Failed to fetch domain analysis");
  }
  return await response.json();
}

export async function fetchUrlScan(fqdn: string): Promise<UrlScanResult> {
  const response = await fetch(`${BASE_URL}/urlscan?domain=${fqdn}`);
  if (!response.ok) {
    throw new Error("Failed to fetch url scan");
  }
  return await response.json();
}
