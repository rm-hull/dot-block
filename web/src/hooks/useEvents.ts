import { dateReviver } from "@/utils/date";
import { skipToken, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";

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

export interface Event {
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
  events: Event[];
  total: number;
  countsBySrc: Record<Source, number>;
}

const initialState: State = {
  events: [],
  total: 0,
  countsBySrc: { DoT: 0, DoH: 0, TCP: 0, UDP: 0 },
};

export function useEvents(sseUrl: string) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["events"],
    queryFn: skipToken,
    initialData: initialState,
  });

  useEffect(() => {
    const es = new EventSource(sseUrl);

    es.onmessage = (e) => {
      const event = JSON.parse(e.data, dateReviver) as Event;

      queryClient.setQueryData<State>(["events"], (old = initialState) => {
        const events = [...old.events, event];
        const trimmed =
          events.length > MAX_ITEMS
            ? events.slice(events.length - MAX_ITEMS)
            : events;

        const key = event.src;
        const countsBySrc = {
          ...old.countsBySrc,
          [key]: (old.countsBySrc[key] ?? 0) + 1,
        };

        return {
          events: trimmed,
          total: old.total + 1,
          countsBySrc,
        };
      });
    };

    es.onerror = (err) => console.error("SSE error", err);

    return () => es.close();
  }, [queryClient, sseUrl]);

  return query;
}
