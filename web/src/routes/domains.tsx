import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  Badge,
  Container,
  For,
  HStack,
  Highlight,
  SegmentGroup,
  Table,
  Text,
} from "@chakra-ui/react";
import { DomainsPortalToolbar } from "@/components/DomainsPortalToolbar";
import { Loading } from "@/components/Loading";
import { toaster } from "@/components/ui/toaster";
import { useMetrics } from "@/hooks/useMetrics";

// eslint-disable-next-line react-refresh/only-export-components
function DomainsPage() {
  const [filterText, setFilterText] = useState<string>("");
  const [value, setValue] = useState<string | null>("Allowed");
  const { data, isLoading, error } = useMetrics();

  if (data === undefined && isLoading) {
    return <Loading />;
  }

  if (error) {
    toaster.create({
      id: "domains",
      title: "Error loading domains",
      description: error.message,
      type: "error",
    });
    return null;
  }
  const domains = value === "Allowed" ? data?.dns_top_domains : data?.dns_top_blocked_domains;
  const trimmedFilterText = filterText.trim().toLowerCase();
  return (
    <Container>
      <DomainsPortalToolbar filterText={filterText} onFilterTextChange={setFilterText} />
      <HStack py={2}>
        <SegmentGroup.Root size="xs" value={value} onValueChange={(e) => setValue(e.value)}>
          <SegmentGroup.Indicator />
          <SegmentGroup.Items items={["Allowed", "Blocked"]} />
        </SegmentGroup.Root>
        <Text color="fg.muted" fontSize="sm">
          {domains?.help}
        </Text>
      </HStack>
      <Table.ScrollArea height="calc(100vh - 61px)">
        <Table.Root size="sm" stickyHeader interactive>
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeader width={65}>#</Table.ColumnHeader>
              <Table.ColumnHeader minWidth={400}>Domain</Table.ColumnHeader>
              <Table.ColumnHeader width={50} />
              <Table.ColumnHeader textAlign="right">Count</Table.ColumnHeader>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            <For
              each={domains?.metrics
                ?.filter((item) =>
                  item.labels?.["hostname"].toLowerCase().includes(trimmedFilterText)
                )
                .toSorted((a, b) => b.value - a.value)}
            >
              {(item, index) => (
                <Table.Row key={index}>
                  <Table.Cell>{index + 1}</Table.Cell>
                  <Table.Cell>
                    <Highlight
                      query={trimmedFilterText}
                      styles={{ bg: "yellow.subtle", color: "yellow.fg" }}
                    >
                      {item.labels?.["hostname"] ?? ""}
                    </Highlight>
                  </Table.Cell>
                  <Table.Cell>
                    {item.labels?.["blocklist"] && <Badge>{item.labels?.["blocklist"]}</Badge>}
                  </Table.Cell>
                  <Table.Cell textAlign="right">{item.value}</Table.Cell>
                </Table.Row>
              )}
            </For>
          </Table.Body>
        </Table.Root>
      </Table.ScrollArea>
    </Container>
  );
}

export const Route = createFileRoute("/domains")({
  component: DomainsPage,
});
