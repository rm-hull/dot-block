import { ASN } from '@/components/ASN';
import { PieChartStat, type DataPoint } from '@/components/PieChartStat';
import { QueryType } from '@/components/QueryType';
import { Result } from '@/components/Result';
import TimeSeriesChart from '@/components/TimeSeriesChart';
import { Timestamp } from '@/components/Timestamp';
import { useEvents } from '@/hooks/useEvents';
import { Badge, Card, Collapsible, Container, Highlight, HStack, Table, Text, VStack } from '@chakra-ui/react'
import { createFileRoute } from '@tanstack/react-router'
import { useContext, useLayoutEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { LuChevronRight } from 'react-icons/lu';
import { NavbarToolbarContext } from '@/components/Navbar';
import { PercentageStat } from '@/components/PercentageStat';
import { EventToolbar, type Status } from '@/components/EventToolbar';
import { TiWarning } from "react-icons/ti";
import { ConnectionIcon } from '@/components/ConnectionIcon';
import { FilterTextField } from '@/components/FilterTextField';


const colors = ["red.subtle", "orange.subtle", "yellow.subtle", "green.subtle", "blue.subtle", "indigo.subtle"]

function toData(data?: Record<string, number>): DataPoint[] {

  if (!data) {
    return [];
  }

  return Object.entries(data)
    .filter(([, value]) => value > 0)
    .map(([name, value], index) => ({ name, value, color: colors[index % colors.length] }))
}

// eslint-disable-next-line react-refresh/only-export-components
function EventPage() {

  const toolbarHostRef = useContext(NavbarToolbarContext);
  const [toolbarHost, setToolbarHost] = useState<HTMLDivElement | null>(null);
  const [status, setStatus] = useState<Status>("active");
  const [filterText, setFilterText] = useState<string>("");
  const { data, isLoading, error } = useEvents("/api/events", status === "paused");

  useLayoutEffect(() => {
    setToolbarHost(toolbarHostRef?.current ?? null);
  }, [toolbarHostRef]);

  if (isLoading) {
    return <div>Loading...</div>
  }

  if (error) {
    return <div>Error: {error.message}</div>
  }

  const trimmedFilterText = filterText.trim().toLowerCase();
  const filteredEvents = (data?.events ?? []).filter((event) => {
    if (!trimmedFilterText) return true;
    return (
      event.domain.toLowerCase().includes(trimmedFilterText) ||
      event.ip.toLowerCase().includes(trimmedFilterText)
    );
  });

  return (
    <Container>
      {toolbarHost ? createPortal(
        <HStack gap={4}>
          <FilterTextField value={filterText} onValueChange={setFilterText} />
          <EventToolbar connected={data?.connected} status={status} onStatusChange={setStatus} />
          <ConnectionIcon connected={data?.connected} active={status === "active"} />
        </HStack>,
        toolbarHost) : null}

      <Collapsible.Root defaultOpen>
        <Collapsible.Trigger
          paddingY="3"
          display="flex"
          gap="2"
          alignItems="center"
        >
          <Collapsible.Indicator
            transition="transform 0.2s"
            _open={{ transform: "rotate(90deg)" }}
          >
            <LuChevronRight />
          </Collapsible.Indicator>
          Show aggregates
        </Collapsible.Trigger>
        <Collapsible.Content>
          <HStack pb={3} alignItems="start">
            <VStack alignItems="normal">
              <Card.Root>
                <Card.Body>
                  <PercentageStat title="Cache" value={data?.cached} total={data?.total} helpText="Hit rate" />
                </Card.Body>
              </Card.Root>
              <Card.Root>
                <Card.Body>
                  <PercentageStat title="Blocklist" value={data?.blocked} total={data?.total} helpText="Blocked URLs" />
                </Card.Body>
              </Card.Root>
            </VStack>
            <Card.Root>
              <Card.Header>Query Type</Card.Header>
              <Card.Body>
                <PieChartStat data={toData(data?.countsByQueryType)} />
              </Card.Body>
            </Card.Root>
            <Card.Root>
              <Card.Header>Result</Card.Header>
              <Card.Body>
                <PieChartStat data={toData(data?.countsByResult)} />
              </Card.Body>
            </Card.Root>
            <Card.Root>
              <Card.Header>Source</Card.Header>
              <Card.Body>
                <PieChartStat data={toData(data?.countsBySrc)} />
              </Card.Body>
            </Card.Root>
            <Card.Root>
              <Card.Header>Requests/minute</Card.Header>
              <Card.Body>
                <TimeSeriesChart data={data?.countsByTimestamp} />
              </Card.Body>
            </Card.Root>
          </HStack>
        </Collapsible.Content>
      </Collapsible.Root>
      <Table.ScrollArea height="calc(100vh - 61px)">
        <Table.Root size="sm" stickyHeader interactive>
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeader width={65}>#</Table.ColumnHeader>
              <Table.ColumnHeader width={100}>Timestamp</Table.ColumnHeader>
              <Table.ColumnHeader width={50}>Query</Table.ColumnHeader>
              <Table.ColumnHeader maxWidth={200}>Domain</Table.ColumnHeader>
              <Table.ColumnHeader width={100}>Result</Table.ColumnHeader>
              <Table.ColumnHeader width={75}>Client IP</Table.ColumnHeader>
              <Table.ColumnHeader maxWidth={200}>ASN</Table.ColumnHeader>
              <Table.ColumnHeader width={75}>Source</Table.ColumnHeader>
              <Table.ColumnHeader width={100}>Status</Table.ColumnHeader>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {filteredEvents.flatMap((event, index, events) => {
              const previous = events[index - 1];
              const gapSize = (!trimmedFilterText && previous) ? previous.seq - event.seq - 1 : 0;
              const rows: React.ReactElement[] = [];

              if (!trimmedFilterText && previous && gapSize > 0) {
                rows.push(
                  <Table.Row key={`gap-${previous.seq}-${event.seq}`}>
                    <Table.Cell colSpan={9} >
                      <HStack gap={4}>
                        <Badge colorPalette="orange"><TiWarning size={16} /> Sequence gap</Badge>{' '}
                        <Text fontSize="xs" color="fg.subtle">{gapSize} missing event{gapSize > 1 ? "s" : ""} between #{event.seq} and #{previous.seq}</Text>
                      </HStack>
                    </Table.Cell>
                  </Table.Row>
                );
              }

              rows.push(
                <Table.Row key={`${event.seq}-${index}`}>
                  <Table.Cell>{event.seq}</Table.Cell>
                  <Table.Cell><Timestamp value={event.ts} /></Table.Cell>
                  <Table.Cell><QueryType rrtype={event.queryType} /></Table.Cell>
                  <Table.Cell truncate maxWidth={200}>
                    <Highlight query={filterText} styles={{ bg: "yellow.subtle", color: "yellow.fg" }}>
                      {event.domain}
                    </Highlight>
                  </Table.Cell>
                  <Table.Cell><Result rcode={event.result} /></Table.Cell>
                  <Table.Cell>
                    <Highlight query={filterText} styles={{ bg: "yellow.subtle", color: "yellow.fg" }}>
                      {event.ip}
                    </Highlight>
                  </Table.Cell>
                  <Table.Cell truncate maxWidth={200}><ASN ipAddr={event.ip} /></Table.Cell>
                  <Table.Cell>{event.src}</Table.Cell>
                  <Table.Cell>{event.blocked && <Badge colorPalette="red">Blocked</Badge>} {event.cached && <Badge colorPalette="purple">Cached</Badge>}</Table.Cell>
                </Table.Row>
              );

              return rows;
            })}
          </Table.Body>
        </Table.Root>
      </Table.ScrollArea>
    </Container>
  )
}


export const Route = createFileRoute('/events')({
  component: EventPage
})
