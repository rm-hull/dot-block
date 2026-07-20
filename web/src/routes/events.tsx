import { ASN } from '@/components/ASN';
import { PieChartStat, type DataPoint } from '@/components/PieChartStat';
import { QueryType } from '@/components/QueryType';
import { Result } from '@/components/Result';
import { Timestamp } from '@/components/Timestamp';
import { useEvents } from '@/hooks/useEvents';
import { Badge, Box, Card, Code, Collapsible, Container, HStack, Stack, Stat, Table, VStack } from '@chakra-ui/react'
import { createFileRoute } from '@tanstack/react-router'
import { LuChevronRight } from 'react-icons/lu';

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

  const { data, isLoading, error } = useEvents("/api/events");

  if (isLoading) {
    return <div>Loading...</div>
  }

  if (error) {
    return <div>Error: {error.message}</div>
  }

  return (
    <Container>
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
          <HStack padding="4" borderWidth="1px" alignItems="start">
            <VStack alignItems="normal">
              <Card.Root>
                <Card.Body>
                  <Stat.Root>
                    <Stat.Label>Cache</Stat.Label>
                    <Stat.ValueText alignItems="baseline">
                      {((data?.cached ?? 0) * 100 / (data?.total ?? 1)).toFixed(1)} <Stat.ValueUnit>%</Stat.ValueUnit>
                    </Stat.ValueText>
                    <Stat.HelpText>Hit rate</Stat.HelpText>
                  </Stat.Root>
                </Card.Body>
              </Card.Root>
              <Card.Root>
                <Card.Body>
                  <Stat.Root>
                    <Stat.Label>Blocklist</Stat.Label>
                    <Stat.ValueText alignItems="baseline">
                      {((data?.blocked ?? 0) * 100 / (data?.total ?? 1)).toFixed(1)} <Stat.ValueUnit>%</Stat.ValueUnit>
                    </Stat.ValueText>
                    <Stat.HelpText>Blocked URLs</Stat.HelpText>
                  </Stat.Root>
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
              <Card.Header>Timestamp</Card.Header>
              <Code>
                <pre>
                  {JSON.stringify(data?.countsByTimestamp, null, 2)}
                </pre>
              </Code>
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
            {data?.events.map((event) => (
              <Table.Row key={event.seq}>
                <Table.Cell>{event.seq}</Table.Cell>
                <Table.Cell><Timestamp value={event.ts} /></Table.Cell>
                <Table.Cell><QueryType rrtype={event.queryType} /></Table.Cell>
                <Table.Cell truncate maxWidth={200}>{event.domain}</Table.Cell>
                <Table.Cell><Result rcode={event.result} /></Table.Cell>
                <Table.Cell>{event.ip}</Table.Cell>
                <Table.Cell truncate maxWidth={200}><ASN ipAddr={event.ip} /></Table.Cell>
                <Table.Cell>{event.src}</Table.Cell>
                <Table.Cell>{event.blocked && <Badge colorPalette="red">Blocked</Badge>} {event.cached && <Badge colorPalette="purple">Cached</Badge>}</Table.Cell>
              </Table.Row>
            ))}
          </Table.Body>
        </Table.Root>
      </Table.ScrollArea>
    </Container>
  )
}


export const Route = createFileRoute('/events')({
  component: EventPage
})
