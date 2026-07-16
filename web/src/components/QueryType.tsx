import type { RRType } from "@/hooks/useEvents"
import { Badge } from "@chakra-ui/react"
import { Tooltip } from "@/components/ui/tooltip";

interface QueryTypeProps {
  rrtype: RRType
}

// RRType mappings
const mapping: Record<RRType, { descr: string }> = {
  A: { descr: "IPv4 host address" },
  AAAA: { descr: "IPv6 host address" },
  CERT: { descr: "Certificate record" },
  CNAME: { descr: "Canonical name alias" },
  HTTPS: { descr: "HTTPS service record" },
  NS: { descr: "Authoritative name server" },
  PTR: { descr: "Pointer to canonical name" },
  MX: { descr: "Mail exchange server" },
  TXT: { descr: "Text record" },
  SOA: { descr: "Start of authority" },
}

export function QueryType({ rrtype }: QueryTypeProps) {
  const { descr } = mapping[rrtype]
  return (
    <Tooltip content={descr}>
      <Badge colorPalette={"gray"}>{rrtype}</Badge>
    </Tooltip>
  );
}
