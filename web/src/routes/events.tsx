import { ASN } from '@/components/ASN';
import { QueryType } from '@/components/QueryType';
import { Result } from '@/components/Result';
import { Timestamp } from '@/components/Timestamp';
import { useEvents, type Event } from '@/hooks/useEvents';
import { Badge, Container, Table } from '@chakra-ui/react'
import { createFileRoute } from '@tanstack/react-router'

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
