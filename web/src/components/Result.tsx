import type { RCode } from "@/hooks/useEvents"
import { Badge } from "@chakra-ui/react"
import { Tooltip } from "@/components/ui/tooltip";

interface ResultProps {
  rcode: RCode
}

// RCode mappings
const mapping: Record<RCode, { descr: string; color: string }> = {
  NOERROR: { descr: "DNS Query completed successfully", color: "green" },
  FORMERR: { descr: "DNS Query format error", color: "orange" },
  SERVFAIL: { descr: "Server failed to complete the DNS request", color: "red" },
  NXDOMAIN: { descr: "Non-existent domain", color: "yellow" },
  NOTIMP: { descr: "Not implemented", color: "purple" },
  REFUSED: { descr: "The server refused to answer the query", color: "red" },
  YXDOMAIN: { descr: "Name exists when it should not", color: "orange" },
  XRRSET: { descr: "RRset exists when it should not", color: "orange" },
  NOTAUTH: { descr: "Server not authoritative for zone", color: "yellow" },
  NOTZONE: { descr: "Name not in zone", color: "purple" },
}

export function Result({ rcode }: ResultProps) {
  const { color, descr } = mapping[rcode] ?? {
    color: "gray",
    descr: `Unknown result code: ${rcode}`,
  }

  return (
    <Tooltip content={descr}>
      <Badge colorPalette={color}>{rcode}</Badge>
    </Tooltip>
  );
}
