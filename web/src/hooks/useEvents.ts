import { dateReviver } from "@/utils/date";
import { skipToken, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

const MAX_ITEMS = 50;

export interface Event {
  ts: Date;
  seq: number;
  domain: string;
  ip: string;
  src: string;
  blocked: boolean;
}

interface State {
  events: Event[];
  total: number;
  countsBySrc: Record<string, number>;
}

const initialState: State = {
  events: [],
  total: 0,
  countsBySrc: {},
};

export function useEvents(sseUrl: string) {
  const [error, setError] = useState<Error | undefined>(undefined);
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
