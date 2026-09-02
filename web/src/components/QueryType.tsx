import { Badge } from "@chakra-ui/react";
import { Tooltip } from "@/components/ui/tooltip";
import type { RRType } from "@/hooks/useEvents";

type QueryTypeProps = { rrtype: RRType; type?: never } | { type: number; rrtype?: never };

// RRType mappings
const mapping: Record<RRType, { type: number; descr: string }> = {
  A: { type: 1, descr: "IPv4 host address" },
  AAAA: { type: 28, descr: "IPv6 host address" },
  CERT: { type: 37, descr: "Certificate record" },
  CNAME: { type: 5, descr: "Canonical name alias" },
  HTTPS: { type: 65, descr: "HTTPS service record" },
  NS: { type: 2, descr: "Authoritative name server" },
  PTR: { type: 12, descr: "Pointer to canonical name" },
  MX: { type: 15, descr: "Mail exchange server" },
  TXT: { type: 16, descr: "Text record" },
  SOA: { type: 6, descr: "Start of authority" },
  SRV: { type: 33, descr: "Server selection" },
};

export const mappingByType: Record<number, { rrtype: RRType; descr: string }> = Object.fromEntries(
  Object.entries(mapping).map(([rrtype, { type, descr }]) => [
    type,
    { rrtype: rrtype as RRType, descr },
  ])
);

export function QueryType(props: QueryTypeProps) {
  const entry = props.rrtype !== undefined ? mapping[props.rrtype] : mappingByType[props.type];
  const displayType = props.rrtype ?? (entry && "rrtype" in entry ? entry.rrtype : props.type);
  const descr = entry?.descr ?? `Unknown record type: ${displayType}`;

  return (
    <Tooltip content={descr}>
      <Badge colorPalette={"gray"}>{displayType}</Badge>
    </Tooltip>
  );
}
