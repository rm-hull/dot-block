import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Container } from "@chakra-ui/react";
import { EventAggregates } from "@/components/EventAggregates";
import { EventPortalToolbar } from "@/components/EventPortalToolbar";
import type { Status } from "@/components/EventStreamControls";
import { EventTable } from "@/components/EventTable";
import { Loading } from "@/components/Loading";
import { toaster } from "@/components/ui/toaster";
import { useEvents } from "@/hooks/useEvents";

// eslint-disable-next-line react-refresh/only-export-components
function EventPage() {
  const [status, setStatus] = useState<Status>("active");
  const [filterText, setFilterText] = useState<string>("");
  const { data, isLoading, error } = useEvents("/api/events", status === "paused");

  if (data === undefined && isLoading) {
    return <Loading />;
  }

  if (error) {
    toaster.create({
      id: "event-stream-status",
      title: "Error loading blocklists",
      description: error.message,
      type: "error",
    });
    return null;
  }

  return (
    <Container>
      <EventPortalToolbar
        filterText={filterText}
        onFilterTextChange={setFilterText}
        status={status}
        onStatusChange={setStatus}
        connected={data?.connected}
      />

      <EventAggregates
        total={data?.total}
        cached={data?.cached}
        blocked={data?.blocked}
        countsByQueryType={data?.countsByQueryType}
        countsByResult={data?.countsByResult}
        countsBySrc={data?.countsBySrc}
        countsByTimestamp={data?.countsByTimestamp}
      />
      <EventTable events={data?.events ?? []} filterText={filterText} />
    </Container>
  );
}

export const Route = createFileRoute("/events")({
  component: EventPage,
});
