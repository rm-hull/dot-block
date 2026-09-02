import { createFileRoute } from "@tanstack/react-router";
import { Badge, Container, HStack, Heading, Link, Table, Text, VStack } from "@chakra-ui/react";
import TimeAgo from "react-time-ago";
import { ActiveAction } from "@/actions/ActiveAction";
import { ReloadAction } from "@/actions/ReloadAction";
import { ErrorSuffix } from "@/components/ErrorSuffix";
import { GlobalKillSwitch } from "@/components/GlobalKillSwitch";
import { Loading } from "@/components/Loading";
import { toaster } from "@/components/ui/toaster";
import { useBlocklists } from "@/hooks/useBlocklists";
import type { Blocklist } from "@/service/blocklists";

function BlocklistsPage() {
  const { data, isLoading, error } = useBlocklists();

  if (data === undefined && isLoading) {
    return <Loading />;
  }

  if (error) {
    toaster.create({
      id: "blocklists",
      title: "Error loading blocklists",
      description: error.message,
      type: "error",
    });
    return null;
  }

  function lastModified(blocklist: Blocklist): Date | undefined {
    const lastModifiedStr =
      blocklist.last_updated ??
      blocklist.metadata?.last_modified ??
      blocklist.metadata?.last_updated ??
      blocklist.metadata?.last_update;
    if (!lastModifiedStr) {
      return undefined;
    }

    const dt = new Date(lastModifiedStr);
    if (Number.isNaN(dt.getTime())) {
      return undefined;
    }

    return dt;
  }

  return (
    <Container>
      <GlobalKillSwitch
        active={
          data?.blocklists?.every((blocklist) => blocklist.disabled_until === undefined) ?? false
        }
      />
      <Table.Root size="sm" stickyHeader interactive>
        <Table.Header>
          <Table.Row>
            <Table.ColumnHeader>Blocklist</Table.ColumnHeader>
            <Table.ColumnHeader width={150}>Last fetched</Table.ColumnHeader>
            <Table.ColumnHeader width={150}>Last updated</Table.ColumnHeader>
            <Table.ColumnHeader width={50} textAlign="right">
              Size
            </Table.ColumnHeader>
            <Table.ColumnHeader width={100}>Schedule</Table.ColumnHeader>
            <Table.ColumnHeader width={70}>Active</Table.ColumnHeader>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {data?.blocklists?.map((blocklist, index) => {
            const modified = lastModified(blocklist);
            return (
              <Table.Row key={index}>
                <Table.Cell maxWidth={500}>
                  <VStack align="start" gap={0}>
                    <Heading size="sm">{blocklist.title}</Heading>
                    <Text fontSize="xs" color="fg.muted">
                      {blocklist.description}
                    </Text>
                    <Link
                      href={blocklist.url}
                      fontSize="xs"
                      colorPalette="blue"
                      target="_blank"
                      wordBreak="break-all"
                      display="ruby"
                    >
                      {blocklist.url} <ErrorSuffix error={blocklist.error} />
                    </Link>
                  </VStack>
                </Table.Cell>
                <Table.Cell>
                  {blocklist.last_fetched === undefined ? (
                    "—"
                  ) : (
                    <HStack gap={0}>
                      <TimeAgo date={blocklist.last_fetched} />
                      <ReloadAction name={blocklist.name} />
                    </HStack>
                  )}
                </Table.Cell>
                <Table.Cell>
                  {modified === undefined ? "—" : <TimeAgo date={modified} />}
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
            );
          })}
        </Table.Body>
      </Table.Root>
    </Container>
  );
}

export const Route = createFileRoute("/blocklists")({
  component: BlocklistsPage,
});
