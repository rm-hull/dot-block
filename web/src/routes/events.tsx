import { ASN } from '@/components/ASN';
import { useEvents, type Event } from '@/hooks/useEvents';
import { Badge, Container, Table } from '@chakra-ui/react'
import { createFileRoute } from '@tanstack/react-router'

function byDescSeq(a: Event, b: Event): number {
  const aSeq = typeof a.seq === 'number' ? a.seq : Number(a.seq ?? 0)
  const bSeq = typeof b.seq === 'number' ? b.seq : Number(b.seq ?? 0)
  return bSeq - aSeq
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
      <Table.ScrollArea height="calc(100vh - 60px)">
        <Table.Root size="sm" stickyHeader interactive>
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeader>#</Table.ColumnHeader>
              <Table.ColumnHeader>Timestamp</Table.ColumnHeader>
              <Table.ColumnHeader>Domain</Table.ColumnHeader>
              <Table.ColumnHeader>Client IP</Table.ColumnHeader>
              <Table.ColumnHeader>ASN</Table.ColumnHeader>
              <Table.ColumnHeader>Source</Table.ColumnHeader>
              <Table.ColumnHeader>Blocked</Table.ColumnHeader>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {data?.events.toSorted(byDescSeq).map((event) => (
              <Table.Row key={event.seq}>
                <Table.Cell>{event.seq}</Table.Cell>
                <Table.Cell>{event.ts.toISOString().slice(11)}</Table.Cell>
                <Table.Cell>{event.domain}</Table.Cell>
                <Table.Cell>{event.ip}</Table.Cell>
                <Table.Cell><ASN ipAddr={"193.54.22.12"} /></Table.Cell>
                <Table.Cell>{event.src}</Table.Cell>
                <Table.Cell>{<Badge colorPalette={event.blocked ? "red" : "green"}>{event.blocked.toString()}</Badge>}</Table.Cell>
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
