import * as Flags from "country-flag-icons/react/3x2";

export interface ASN {
  iso_code: keyof typeof Flags;
  country: string;
  asn: string;
  provider: string;
  domain: string;
}

export async function fetchASN(ipAddr: string): Promise<ASN | null> {
  const response = await fetch(`/api/asn/${ipAddr}`);
  if (response.status === 404) {
    return null;
  }
  return response.json();
}
