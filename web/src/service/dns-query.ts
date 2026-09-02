export interface DnsQuestion {
  name: string;
  type: number;
}

export interface DnsRecord {
  name: string;
  type: number;
  TTL: number;
  data: string[];
}

export interface DnsQueryResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question?: DnsQuestion[];
  Answer?: DnsRecord[];
  Authority?: DnsRecord[];
  Comment?: string;
}

export async function fetchDnsQuery(fqdn: string): Promise<DnsQueryResponse> {
  const url = `/api/dns-query?name=${fqdn}&type=A`;
  const response = await fetch(url, {
    headers: {
      Accept: "application/dns-json",
    },
  });

  if (!response.ok) {
    throw new Error(response.statusText);
  }

  return await response.json();
}
