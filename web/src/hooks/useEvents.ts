import { dateReviver } from "@/utils/date";
import { skipToken, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

const MAX_ITEMS = 50;

// Commmon RCodes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6 for full list
export type RCode =
  | "NOERROR"
  | "FORMERR"
  | "SERVFAIL"
  | "NXDOMAIN"
  | "NOTIMP"
  | "REFUSED"
  | "YXDOMAIN"
  | "XRRSET"
  | "NOTAUTH"
  | "NOTZONE";

// Common RRTypes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4 for full list
export type RRType =
  | "A"
  | "AAAA"
  | "CERT"
  | "CNAME"
  | "HTTPS"
  | "NS"
  | "PTR"
  | "MX"
  | "TXT"
  | "SOA";

export type Source = "TCP" | "UDP" | "DoH" | "DoT";

export interface DnsEvent {
  ts: Date;
  seq: number;
  queryType: RRType;
  domain: string;
  result: RCode;
  ip: string;
  src: Source;
  blocked: boolean;
  cached: boolean;
}

interface State {
  events: DnsEvent[];
  total: number;
  countsBySrc: Record<Source, number>;
}

const initialState: State = {
  events: [],
  total: 0,
  countsBySrc: { DoT: 0, DoH: 0, TCP: 0, UDP: 0 },
};

export function useEvents(sseUrl: string, batchIntervalMs = 250) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["events"],
    queryFn: skipToken,
    initialData: initialState,
  });

  // Buffer of events received since the last flush.
  const bufferRef = useRef<DnsEvent[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const es = new EventSource(sseUrl);

    const flush = () => {
      timerRef.current = null;
      if (bufferRef.current.length === 0) return;

      const batch = bufferRef.current;
      bufferRef.current = [];

      queryClient.setQueryData<State>(["events"], (old = initialState) => {
        // batch arrived oldest->newest; prepend newest-first to match existing order
        const events = [...batch].reverse().concat(old.events);
        const trimmed =
          events.length > MAX_ITEMS ? events.slice(0, MAX_ITEMS) : events;

        const countsBySrc = { ...old.countsBySrc };
        for (const event of batch) {
          countsBySrc[event.src] = (countsBySrc[event.src] ?? 0) + 1;
        }

        return {
          events: trimmed,
          total: old.total + batch.length,
          countsBySrc,
        };
      });
    };

    es.onmessage = (e) => {
      let event: DnsEvent;
      try {
        event = JSON.parse(e.data, dateReviver) as DnsEvent;
      } catch (err) {
        console.error("Failed to parse SSE event", err, e.data);
        return;
      }
      bufferRef.current.push(event);

      // Schedule a flush if one isn't already pending (throttle, not debounce).
      if (timerRef.current === null) {
        timerRef.current = setTimeout(flush, batchIntervalMs);
      }
    };

    es.onerror = (err) => console.error("SSE error", err);

    return () => {
      es.close();
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      bufferRef.current = [];
    };
  }, [queryClient, sseUrl, batchIntervalMs]);

  return query;
}
