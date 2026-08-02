import { createFileRoute } from "@tanstack/react-router";
import { Badge, Container, HStack, Heading, Link, Table, Text, VStack } from "@chakra-ui/react";
import TimeAgo from "react-time-ago";
import { ActiveAction } from "@/actions/ActiveAction";
import { ReloadAction } from "@/actions/ReloadAction";
import { FreshSuffix } from "@/components/FreshSuffix";
import { useBlocklists } from "@/hooks/useBlocklists";
import { toaster } from "@/components/ui/toaster";
import { Loading } from "@/components/Loading";

function BlocklistsPage() {
  const { data, isLoading, error } = useBlocklists();

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
      <Table.Root size="sm" stickyHeader interactive>
        <Table.Header>
          <Table.Row>
            <Table.ColumnHeader>Blocklist</Table.ColumnHeader>
            <Table.ColumnHeader width={150}>Last updated</Table.ColumnHeader>
            <Table.ColumnHeader width={50} textAlign="right">
              Size
            </Table.ColumnHeader>
            <Table.ColumnHeader width={100}>Schedule</Table.ColumnHeader>
            <Table.ColumnHeader width={70}>Active</Table.ColumnHeader>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {data?.blocklists?.map((blocklist, index) => (
            <Table.Row key={index}>
              <Table.Cell maxWidth={500}>
                <VStack align="start" gap={0}>
                  <Heading size="sm">{blocklist.metadata?.title}</Heading>
                  <Text fontSize="xs" color="fg.muted">
                    {blocklist.metadata?.description}
                  </Text>
                  <Link
                    href={blocklist.url}
                    fontSize="xs"
                    colorPalette="blue"
                    wordBreak="break-all"
                    display="ruby"
                  >
                    {blocklist.url} <FreshSuffix url={blocklist.url} />
                  </Link>
                </VStack>
              </Table.Cell>
              <Table.Cell>
                <HStack gap={0}>
                  <TimeAgo date={blocklist.last_updated} />
                  <ReloadAction name={blocklist.name} />
                </HStack>
              </Table.Cell>
              <Table.Cell textAlign="right">{blocklist.size}</Table.Cell>
              <Table.Cell>
                <Badge colorPalette="orange">{blocklist.schedule}</Badge>
              </Table.Cell>
              <Table.Cell width={150}>
                <HStack gap={1}>
                  <ActiveAction
                    name={blocklist.name}
                    active={blocklist.disabled_until === undefined}
                  />
                  {blocklist.disabled_until && (
                    <Text fontSize="xs" color="fg.muted" lineHeight={1.25}>
                      Re-enabled <TimeAgo date={blocklist.disabled_until} />
                    </Text>
                  )}
                </HStack>
              </Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </Table.Root>
    </Container>
  );
}

export const Route = createFileRoute("/blocklists")({
  component: BlocklistsPage,
});
