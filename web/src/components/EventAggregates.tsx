import { Card, Collapsible, HStack, VStack } from "@chakra-ui/react";
import { LuChevronRight } from "react-icons/lu";
import { PercentageStat } from "@/components/PercentageStat";
import { type DataPoint, PieChartStat } from "@/components/PieChartStat";
import TimeSeriesChart from "@/components/TimeSeriesChart";

const colors = [
  "red.subtle",
  "orange.subtle",
  "yellow.subtle",
  "green.subtle",
  "blue.subtle",
  "indigo.subtle",
];

function toData(data?: Record<string, number>): DataPoint[] {
  if (!data) {
    return [];
  }

  return Object.entries(data)
    .filter(([, value]) => value > 0)
    .map(([name, value], index) => ({ name, value, color: colors[index % colors.length] }));
}

interface EventAggregatesProps {
  total?: number;
  cached?: number;
  blocked?: number;
  countsByQueryType?: Record<string, number>;
  countsByResult?: Record<string, number>;
  countsBySrc?: Record<string, number>;
  countsByTimestamp?: Record<string, number>;
}

export function EventAggregates({
  total,
  cached,
  blocked,
  countsByQueryType,
  countsByResult,
  countsBySrc,
  countsByTimestamp,
}: EventAggregatesProps) {
  return (
    <Collapsible.Root defaultOpen>
      <Collapsible.Trigger paddingY="3" display="flex" gap="2" alignItems="center">
        <Collapsible.Indicator transition="transform 0.2s" _open={{ transform: "rotate(90deg)" }}>
          <LuChevronRight />
        </Collapsible.Indicator>
        Show aggregates
      </Collapsible.Trigger>
      <Collapsible.Content>
        <HStack pb={3} alignItems="start">
          <VStack alignItems="normal" alignSelf="stretch">
            <Card.Root flex="1 1 auto">
              <Card.Body>
                <PercentageStat title="Cache" value={cached} total={total} helpText="Hit rate" />
              </Card.Body>
            </Card.Root>
            <Card.Root flex="1 1 auto">
              <Card.Body>
                <PercentageStat
                  title="Blocklist"
                  value={blocked}
                  total={total}
                  helpText="Blocked URLs"
                />
              </Card.Body>
            </Card.Root>
          </VStack>
          <Card.Root>
            <Card.Header>Query Type</Card.Header>
            <Card.Body>
              <PieChartStat data={toData(countsByQueryType)} />
            </Card.Body>
          </Card.Root>
          <Card.Root>
            <Card.Header>Result</Card.Header>
            <Card.Body>
              <PieChartStat data={toData(countsByResult)} />
            </Card.Body>
          </Card.Root>
          <Card.Root>
            <Card.Header>Source</Card.Header>
            <Card.Body>
              <PieChartStat data={toData(countsBySrc)} />
            </Card.Body>
          </Card.Root>
          <Card.Root>
            <Card.Header>Requests/minute</Card.Header>
            <Card.Body>
              <TimeSeriesChart data={countsByTimestamp} />
            </Card.Body>
          </Card.Root>
        </HStack>
      </Collapsible.Content>
    </Collapsible.Root>
  );
}
