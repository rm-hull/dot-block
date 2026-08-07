import { Badge, HStack, Highlight, Table, Text } from "@chakra-ui/react";
import { TbTimelineEventText } from "react-icons/tb";
import { TiWarning } from "react-icons/ti";
import { ASN } from "@/components/ASN";
import { QueryType } from "@/components/QueryType";
import { Result } from "@/components/Result";
import { Timestamp } from "@/components/Timestamp";
import { EmptyState } from "@/components/ui/empty-state";
import type { DnsEvent } from "@/hooks/useEvents";

interface EventTableProps {
  events: DnsEvent[];
  filterText: string;
}

interface GapRowProps {
  previousSeq: number;
  currentSeq: number;
  gapSize: number;
}

function GapRow({ previousSeq, currentSeq, gapSize }: GapRowProps) {
  return (
    <Table.Row key={`gap-${previousSeq}-${currentSeq}`}>
      <Table.Cell colSpan={9}>
        <HStack gap={4}>
          <Badge colorPalette="orange">
            <TiWarning size={16} /> Sequence gap
          </Badge>{" "}
          <Text fontSize="xs" color="fg.subtle">
            {gapSize} missing event{gapSize > 1 ? "s" : ""} between #{currentSeq} and #{previousSeq}
          </Text>
        </HStack>
      </Table.Cell>
    </Table.Row>
  );
}

interface EventRowProps {
  event: DnsEvent;
  index: number;
  filterText: string;
}

function EventRow({ event, index, filterText }: EventRowProps) {
  return (
    <Table.Row key={`${event.seq}-${index}`}>
      <Table.Cell fontFamily="mono" letterSpacing={-1.2}>
        {event.seq}
      </Table.Cell>
      <Table.Cell>
        <Timestamp value={event.ts} />
      </Table.Cell>
      <Table.Cell>
        <QueryType rrtype={event.queryType} />
      </Table.Cell>
      <Table.Cell truncate maxWidth={200}>
        <Highlight query={filterText} styles={{ bg: "yellow.subtle", color: "yellow.fg" }}>
          {event.domain}
        </Highlight>
      </Table.Cell>
      <Table.Cell textAlign="right">{event.answers}</Table.Cell>
      <Table.Cell>
        <Result rcode={event.result} />
      </Table.Cell>
      <Table.Cell>
        <Highlight query={filterText} styles={{ bg: "yellow.subtle", color: "yellow.fg" }}>
          {event.ip}
        </Highlight>
      </Table.Cell>
      <Table.Cell truncate maxWidth={200}>
        <ASN ipAddr={event.ip} />
      </Table.Cell>
      <Table.Cell>{event.src}</Table.Cell>
      <Table.Cell>
        {event.blocked && <Badge colorPalette="red">Blocked</Badge>}{" "}
        {event.cached && <Badge colorPalette="purple">Cached</Badge>}
      </Table.Cell>
    </Table.Row>
  );
}

export function EventTable({ events, filterText }: EventTableProps) {
  const trimmedFilterText = filterText.trim().toLowerCase();
  const filteredEvents = events.filter((event) => {
    if (!trimmedFilterText) return true;
    return (
      event.domain.toLowerCase().includes(trimmedFilterText) ||
      event.ip.toLowerCase().includes(trimmedFilterText)
    );
  });

  if (filteredEvents.length === 0) {
    return (
      <EmptyState
        py={12}
        title="No events found"
        description={
          trimmedFilterText ? `No events matching "${filterText}"` : "No DNS events recorded yet."
        }
        icon={<TbTimelineEventText />}
      />
    );
  }

  return (
    <Table.ScrollArea height="calc(100vh - 61px)">
      <Table.Root size="sm" stickyHeader interactive>
        <Table.Header>
          <Table.Row>
            <Table.ColumnHeader width={65}>#</Table.ColumnHeader>
            <Table.ColumnHeader width={100}>Timestamp</Table.ColumnHeader>
            <Table.ColumnHeader width={50}>Query</Table.ColumnHeader>
            <Table.ColumnHeader maxWidth={200}>Domain</Table.ColumnHeader>
            <Table.ColumnHeader width={50}>Answers</Table.ColumnHeader>
            <Table.ColumnHeader width={100}>Result</Table.ColumnHeader>
            <Table.ColumnHeader width={75}>Client IP</Table.ColumnHeader>
            <Table.ColumnHeader maxWidth={200}>ASN</Table.ColumnHeader>
            <Table.ColumnHeader width={75}>Source</Table.ColumnHeader>
            <Table.ColumnHeader width={100}>Status</Table.ColumnHeader>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {filteredEvents.flatMap((event, index, eventsList) => {
            const previous = eventsList[index - 1];
            const gapSize = !trimmedFilterText && previous ? previous.seq - event.seq - 1 : 0;
            const rows: React.ReactElement[] = [];

            if (!trimmedFilterText && previous && gapSize > 0) {
              rows.push(
                <GapRow
                  key={`gap-${previous.seq}-${event.seq}`}
                  previousSeq={previous.seq}
                  currentSeq={event.seq}
                  gapSize={gapSize}
                />
              );
            }

            rows.push(
              <EventRow
                key={`${event.seq}-${index}`}
                event={event}
                index={index}
                filterText={filterText}
              />
            );

            return rows;
          })}
        </Table.Body>
      </Table.Root>
    </Table.ScrollArea>
  );
}
