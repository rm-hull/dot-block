import { useEffect, useRef } from "react";
import { skipToken, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchEventSource } from "@microsoft/fetch-event-source";
import { getApiKey } from "@/service/auth";
import { dateReviver } from "@/utils/date";

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
  "SRV",
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
  answers: number;
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
  Object.fromEntries(values.map((value) => [value, 0])) as Record<T[number], number>;

const incrementCount = <K extends PropertyKey>(counts: Record<K, number>, key: K) => {
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

type Options = {
  maxItems: number;
  batchIntervalMs: number;
  heartbeatTimeoutMs: number;
};

const MAX_RETRY_DELAY_MS = 30_000;

function computeRetryDelay(retryCount: number): number {
  const delay = Math.pow(2, retryCount) * 1000; // Exponential backoff: 1s, 2s, 4s, 8s, etc.
  return Math.min(delay, MAX_RETRY_DELAY_MS);
}

export function useEvents(
  sseUrl: string,
  paused = false,
  options: Options = {
    maxItems: 100,
    batchIntervalMs: 100,
    heartbeatTimeoutMs: 15000,
  }
) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["events"],
    queryFn: skipToken,
    initialData: initial,
  });

  // Buffer of events received since the last flush.
  const bufferRef = useRef<DnsEvent[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pausedRef = useRef(paused);

  useEffect(() => {
    pausedRef.current = paused;

    if (paused) {
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      bufferRef.current = [];
    }
  }, [paused]);

  useEffect(() => {
    let ctrl = new AbortController();

    const setupEventSource = () => {
      fetchEventSource(sseUrl, {
        method: "GET",
        headers: {
          Accept: "text/event-stream",
          "X-API-Key": getApiKey() || "",
        },
        signal: ctrl.signal,
        async onopen(response) {
          if (response.ok) {
            retryCount = 0;
            resetHeartbeat();
            queryClient.setQueryData<EventFeed>(["events"], (old = initial) => ({
              ...old,
              connected: true,
            }));
          } else {
            throw new Error(`Failed to connect to SSE: ${response.status}`);
          }
        },
        onmessage(e) {
          if (e.event === "ping") {
            resetHeartbeat();
            return;
          }
          resetHeartbeat();
          let event: DnsEvent;
          try {
            event = JSON.parse(e.data, dateReviver) as DnsEvent;
          } catch (err) {
            console.error("[useEvents] Failed to parse SSE event:", err, e.data);
            return;
          }
          if (pausedRef.current) return;

          bufferRef.current.push(event);

          if (timerRef.current === null) {
            timerRef.current = setTimeout(flush, options.batchIntervalMs);
          }
        },
        onerror(err) {
          console.error("[useEvents] SSE error:", err);
          if (heartbeatTimer !== null) {
            clearTimeout(heartbeatTimer);
            heartbeatTimer = null;
          }
          queryClient.setQueryData<EventFeed>(["events"], (old) => {
            if (!old) return old;
            return { ...old, connected: false };
          });
          throw err;
        },
        onclose() {
          if (!isClosed) {
            const delay = computeRetryDelay(retryCount++);
            setTimeout(setupEventSource, delay);
          }
        },
      });
    };

    let isClosed = false;
    let retryCount = 0;
    let heartbeatTimer: ReturnType<typeof setTimeout> | null = null;

    const resetHeartbeat = () => {
      if (heartbeatTimer !== null) clearTimeout(heartbeatTimer);
      heartbeatTimer = setTimeout(() => {
        console.warn("[useEvents] Heartbeat timed out");
        queryClient.setQueryData<EventFeed>(["events"], (old) => {
          if (!old) return old;
          return { ...old, connected: false };
        });
        ctrl.abort();
      }, options.heartbeatTimeoutMs);
    };

    // ... (flush implementation omitted for brevity, logic remains)

    const flush = () => {
      timerRef.current = null;
      if (pausedRef.current || bufferRef.current.length === 0) return;

      const batch = bufferRef.current;
      bufferRef.current = [];

      queryClient.setQueryData<EventFeed>(["events"], (old = initial) => {
        const events = [...batch].reverse().concat(old.events);
        const trimmed =
          events.length > options.maxItems ? events.slice(0, options.maxItems) : events;

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
          incrementCount(countsByTimestamp, Math.floor(event.ts.getTime() / 60000) * 60000);

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

    setupEventSource();

    return () => {
      isClosed = true;
      ctrl.abort();
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      bufferRef.current = [];
    };
  }, [queryClient, sseUrl, options.batchIntervalMs, options.heartbeatTimeoutMs, options.maxItems]);

  return query;
}
