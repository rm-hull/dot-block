import * as Flags from "country-flag-icons/react/3x2";

export interface ASN {
  iso_code: keyof typeof Flags;
  country: string;
  asn: string;
  provider: string;
  domain: string;
}

export async function fetchASN(ipAddr: string): Promise<ASN> {
  const response = await fetch(`/api/asn/${ipAddr}`);
  if (!response.ok) {
    throw new Error("Failed to fetch ASN geo-deta");
  }
  return response.json();
}
