import { Badge } from "@chakra-ui/react";
import { Tooltip } from "@/components/ui/tooltip";
import type { RCode } from "@/hooks/useEvents";

type ResultProps = { rcode: RCode; code?: never } | { code: number; rcode?: never };

// RCode mappings
const mapping: Record<RCode, { code: number; descr: string; color: string }> = {
  NOERROR: { code: 0, descr: "DNS Query completed successfully", color: "green" },
  FORMERR: { code: 1, descr: "DNS Query format error", color: "orange" },
  SERVFAIL: { code: 2, descr: "Server failed to complete the DNS request", color: "red" },
  NXDOMAIN: { code: 3, descr: "Non-existent domain", color: "yellow" },
  NOTIMP: { code: 4, descr: "Not implemented", color: "purple" },
  REFUSED: { code: 5, descr: "The server refused to answer the query", color: "red" },
  YXDOMAIN: { code: 6, descr: "Name exists when it should not", color: "orange" },
  XRRSET: { code: 7, descr: "RRset exists when it should not", color: "orange" },
  NOTAUTH: { code: 9, descr: "Server not authoritative for zone", color: "yellow" },
  NOTZONE: { code: 10, descr: "Name not in zone", color: "purple" },
};

export const mappingByCode: Record<number, { rcode: RCode; descr: string; color: string }> =
  Object.fromEntries(
    Object.entries(mapping).map(([rcode, { code, descr, color }]) => [
      code,
      { rcode: rcode as RCode, descr, color },
    ])
  );

export function Result(props: ResultProps) {
  const entry = props.rcode !== undefined ? mapping[props.rcode] : mappingByCode[props.code];
  const displayCode = props.rcode ?? (entry && "rcode" in entry ? entry.rcode : props.code);
  const { color, descr } = entry ?? {
    color: "gray",
    descr: `Unknown result code: ${displayCode}`,
  };

  return (
    <Tooltip content={descr}>
      <Badge colorPalette={color}>{displayCode}</Badge>
    </Tooltip>
  );
}
