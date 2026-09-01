export interface UrlScanResult {
  _id: string;
  _score?: number;
  sort: any[];
  result: string;
  screenshot: string;
  submitter: Record<string, never>;
  canonical: UrlScanCanonical;
  task: UrlScanTask;
  stats: UrlScanStats;
  files?: UrlScanFile[];
  page: UrlScanPage;
}

export interface UrlScanFile {
  filename: string;
  sha256: string;
  filesize: number;
  state: string;
  mimeType: string;
  mimeDescription: string;
  url: string;
}

export interface UrlScanCanonical {
  task: {
    url: string;
  };
  page: {
    url: string;
  };
}

export interface UrlScanTask {
  visibility: string;
  method: string;
  domain: string;
  apexDomain: string;
  time: Date; // ISO Date string
  uuid: string;
  url: string;
}

export interface UrlScanStats {
  uniqIPs: number;
  uniqCountries: number;
  dataLength: number;
  encodedDataLength: number;
  requests: number;
}

export interface UrlScanPage {
  country?: string;
  server: string;
  redirected?: string;
  ip: string;
  apexDomainAgeDays: number;
  mimeType: string;
  url: string;
  tlsValidDays: number;
  tlsAgeDays: number;
  ptr?: string;
  domainAgeDays: number;
  tlsValidFrom: Date; // ISO Date string
  domain: string;
  umbrellaRank: number;
  apexDomain: string;
  asnname: string;
  asn: string;
  tlsIssuer: string;
  status: string;
}

export interface ErrorResponse {
  error: string;
}

export function isError(maybeError: unknown): maybeError is ErrorResponse {
  return (
    typeof maybeError === "object" &&
    maybeError !== null &&
    "error" in maybeError &&
    typeof maybeError.error === "string"
  );
}
