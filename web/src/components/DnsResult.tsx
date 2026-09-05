import { For, HStack, Stack, Table, Text } from "@chakra-ui/react";
import { QueryType } from "@/components/QueryType";
import { Result } from "@/components/Result";
import { useDnsQuery } from "@/hooks/useDnsQuery";
import type { DnsQueryResponse, DnsRecord } from "@/service/dns-query";
import { Loading } from "./Loading";
import { StatusFlag, statusFlags } from "./StatusFlag";
import { toaster } from "./ui/toaster";

interface DnsResultProps {
  fqdn: string;
}

interface RecordSectionProps {
  title: string;
  records: DnsRecord[];
}

interface DnsResponseProps {
  response: DnsQueryResponse;
}

function RecordSection({ title, records }: RecordSectionProps) {
  if (records.length === 0) {
    return null;
  }

  return (
    <Stack gap={2}>
      <Text fontSize="sm" fontWeight="semibold">
        {title}
      </Text>
      <Table.ScrollArea maxW="100%">
        <Table.Root size="sm">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeader>Domain</Table.ColumnHeader>
              <Table.ColumnHeader>Type</Table.ColumnHeader>
              <Table.ColumnHeader>TTL</Table.ColumnHeader>
              <Table.ColumnHeader>Data</Table.ColumnHeader>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            <For each={records}>
              {(record, index) => (
                <Table.Row
                  verticalAlign="top"
                  key={`${record.name}-${record.type}-${record.data}-${index}`}
                >
                  <Table.Cell fontFamily="mono" fontSize="xs">
                    {record.name}
                  </Table.Cell>
                  <Table.Cell>
                    <QueryType type={record.type} />
                  </Table.Cell>
                  <Table.Cell whiteSpace="nowrap">{record.TTL}s</Table.Cell>
                  <Table.Cell wordBreak="break-word">
                    <For each={record.data}>
                      {(data, index) => (
                        <Text key={index} fontFamily="mono" fontSize="xs">
                          {data}
                        </Text>
                      )}
                    </For>
                  </Table.Cell>
                </Table.Row>
              )}
            </For>
          </Table.Body>
        </Table.Root>
      </Table.ScrollArea>
    </Stack>
  );
}

function DnsResponse({ response }: DnsResponseProps) {
  const questions = response.Question ?? [];
  const answers = response.Answer ?? [];
  const authority = response.Authority ?? [];

  return (
    <Stack gap={5}>
      <HStack gap={2} wrap="wrap">
        Status:
        <Result code={response.Status} />
        Flags:
        {statusFlags.map((flag) => (
          <StatusFlag key={flag} flag={flag} disabled={!response[flag]} />
        ))}
        {response.Comment && (
          <Text fontSize="sm" color="fg.muted">
            "{response.Comment}"
          </Text>
        )}
      </HStack>

      {questions.length > 0 && (
        <Stack gap={2}>
          <Text fontSize="sm" fontWeight="semibold">
            Question
          </Text>
          <Table.Root size="sm">
            <Table.Header>
              <Table.Row>
                <Table.ColumnHeader>Domain</Table.ColumnHeader>
                <Table.ColumnHeader>Type</Table.ColumnHeader>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {questions.map((question, index) => (
                <Table.Row key={`${question.name}-${question.type}-${index}`}>
                  <Table.Cell fontFamily="mono" fontSize="xs">
                    {question.name}
                  </Table.Cell>
                  <Table.Cell>
                    <QueryType type={question.type} />
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table.Root>
        </Stack>
      )}

      <RecordSection title="Answer" records={answers} />
      <RecordSection title="Authority" records={authority} />
    </Stack>
  );
}

export function DnsResult({ fqdn }: DnsResultProps) {
  const { data, isLoading, error } = useDnsQuery(fqdn);

  if (data === undefined && isLoading) {
    return <Loading />;
  }

  if (error) {
    toaster.create({
      id: "domain-analysis",
      title: `Error loading DNS results for: ${fqdn}`,
      description: error.message,
      type: "error",
    });
    return null;
  }

  if (data === undefined) {
    return null;
  }

  return <DnsResponse response={data} />;
}
