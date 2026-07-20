import { dateReviver } from "@/utils/date";
import { skipToken, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

const MAX_ITEMS = 50;

// Commmon RCodes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6 for full list
const rCodes = [
  "NOERROR",
  "FORMERR",
  "SERVFAIL",
  "NXDOMAIN",
  "NOTIMP",
  "REFUSED",
  "YXDOMAIN",
  "XRRSET",
  "NOTAUTH",
  "NOTZONE",
] as const;
export type RCode = (typeof rCodes)[number];

// Common RRTypes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4 for full list
const rrTypes = [
  "A",
  "AAAA",
  "CERT",
  "CNAME",
  "HTTPS",
  "NS",
  "PTR",
  "MX",
  "TXT",
  "SOA",
] as const;
export type RRType = (typeof rrTypes)[number];

const sources = ["TCP", "UDP", "DoH", "DoT"] as const;
export type Source = (typeof sources)[number];

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

interface EventFeed {
  events: DnsEvent[];
  total: number;
  cached: number;
  blocked: number;
  connected: boolean;
  countsBySrc: Record<Source, number>;
  countsByQueryType: Record<RRType, number>;
  countsByResult: Record<RCode, number>;
  countsByTimestamp: Record<number, number>;
}

const createZeroedCounts = <T extends readonly string[]>(values: T) =>
  Object.fromEntries(values.map((value) => [value, 0])) as Record<
    T[number],
    number
  >;

const incrementCount = <K extends PropertyKey>(
  counts: Record<K, number>,
  key: K,
) => {
  counts[key] = (counts[key] ?? 0) + 1;
};

const initial: EventFeed = {
  events: [],
  total: 0,
  cached: 0,
  blocked: 0,
  connected: false,
  countsBySrc: createZeroedCounts(sources),
  countsByQueryType: createZeroedCounts(rrTypes),
  countsByResult: createZeroedCounts(rCodes),
  countsByTimestamp: {},
};

export function useEvents(sseUrl: string, batchIntervalMs = 100) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["events"],
    queryFn: skipToken,
    initialData: initial,
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

      queryClient.setQueryData<EventFeed>(["events"], (old = initial) => {
        // batch arrived oldest->newest; prepend newest-first to match existing order
        const events = [...batch].reverse().concat(old.events);
        const trimmed =
          events.length > MAX_ITEMS ? events.slice(0, MAX_ITEMS) : events;

        const countsBySrc = { ...old.countsBySrc };
        const countsByQueryType = { ...old.countsByQueryType };
        const countsByResult = { ...old.countsByResult };
        const countsByTimestamp = { ...old.countsByTimestamp };

        let cached = 0;
        let blocked = 0;

        for (const event of batch) {
          incrementCount(countsBySrc, event.src);
          incrementCount(countsByQueryType, event.queryType);
          incrementCount(countsByResult, event.result);

          // Floor to the nearest minute
          incrementCount(
            countsByTimestamp,
            Math.floor(event.ts.getTime() / 60000) * 60000,
          );

          if (event.cached) cached++;
          if (event.blocked) blocked++;
        }

        return {
          events: trimmed,
          total: old.total + batch.length,
          cached: old.cached + cached,
          blocked: old.blocked + blocked,
          connected: old.connected,
          countsBySrc,
          countsByQueryType,
          countsByResult,
          countsByTimestamp,
        };
      });
    };

    es.onopen = () => {
      queryClient.setQueryData<EventFeed>(["events"], (old = initial) => ({
        ...old,
        connected: true,
      }));
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

    es.onerror = (err) => {
      console.error("SSE error", err);
      queryClient.setQueryData<EventFeed>(["events"], (old = initial) => ({
        ...old,
        connected: false,
      }));
    };

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
