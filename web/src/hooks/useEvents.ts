import { useEffect, useRef } from "react";
import { skipToken, useQuery, useQueryClient } from "@tanstack/react-query";
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
    const setupEventSource = () => {
      const es = new EventSource(sseUrl);
      let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
      let heartbeatTimer: ReturnType<typeof setTimeout> | null = null;

      const resetHeartbeat = () => {
        if (heartbeatTimer !== null) {
          clearTimeout(heartbeatTimer);
        }
        // If no activity is received for 15 seconds, consider connection lost.
        heartbeatTimer = setTimeout(() => {
          console.warn("[useEvents] Heartbeat timed out, marking disconnected and reconnecting...");
          queryClient.setQueryData<EventFeed>(["events"], (old) => {
            if (!old) return old;
            return {
              ...old,
              connected: false,
            };
          });
          es.close();
          if (reconnectTimer === null) {
            const delay = computeRetryDelay(retryCount++);
            reconnectTimer = setTimeout(() => {
              reconnectTimer = null;
              if (!isClosed) {
                setupEventSource();
              }
            }, delay);
          }
        }, options.heartbeatTimeoutMs);
      };

      const flush = () => {
        timerRef.current = null;
        if (pausedRef.current || bufferRef.current.length === 0) return;

        const batch = bufferRef.current;
        bufferRef.current = [];

        queryClient.setQueryData<EventFeed>(["events"], (old = initial) => {
          // batch arrived oldest->newest; prepend newest-first to match existing order
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

      es.onopen = () => {
        retryCount = 0;
        if (reconnectTimer !== null) {
          clearTimeout(reconnectTimer);
          reconnectTimer = null;
        }
        resetHeartbeat();
        queryClient.setQueryData<EventFeed>(["events"], (old = initial) => ({
          ...old,
          connected: true,
        }));
      };

      es.onmessage = (e) => {
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

        // Schedule a flush if one isn't already pending (throttle, not debounce).
        if (timerRef.current === null) {
          timerRef.current = setTimeout(flush, options.batchIntervalMs);
        }
      };

      es.addEventListener("ping", resetHeartbeat);
      es.onerror = (err) => {
        console.error("[useEvents] SSE error:", err);

        if (heartbeatTimer !== null) {
          clearTimeout(heartbeatTimer);
          heartbeatTimer = null;
        }

        // Ensure we mark as disconnected immediately when an error is caught.
        queryClient.setQueryData<EventFeed>(["events"], (old) => {
          if (!old) return old;
          return {
            ...old,
            connected: false,
          };
        });

        // Close the current EventSource to prevent browser's native reconnection.
        es.close();

        // Schedule a reconnection attempt with exponential backoff.
        if (reconnectTimer === null) {
          const delay = computeRetryDelay(retryCount++);
          reconnectTimer = setTimeout(() => {
            reconnectTimer = null;
            if (!isClosed) {
              setupEventSource();
            }
          }, delay);
        }
      };

      currentEs = es;
    };

    let isClosed = false;
    let currentEs: EventSource | null = null;
    let retryCount = 0;

    setupEventSource();

    return () => {
      isClosed = true;
      if (currentEs) {
        currentEs.close();
      }
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      bufferRef.current = [];
    };
  }, [queryClient, sseUrl, options.batchIntervalMs, options.heartbeatTimeoutMs, options.maxItems]);

  return query;
}
