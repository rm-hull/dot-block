import {
  AbsoluteCenter,
  Badge,
  Box,
  Container,
  Field,
  For,
  HStack,
  Heading,
  List,
  ProgressCircle,
  Text,
  VStack,
  Wrap,
} from "@chakra-ui/react";
import { toaster } from "@/components/ui/toaster";
import { useDomainAnalysis } from "@/hooks/useDomainAnalysis";
import { Loading } from "./Loading";
import { Tooltip } from "./ui/tooltip";

function riskColor(value: number | undefined) {
  if (value === undefined || Number.isNaN(value)) {
    return "gray";
  }

  if (value >= 66) {
    return "red";
  }

  if (value >= 33) {
    return "orange";
  }

  return "green";
}

interface DomainAnalysisProps {
  fqdn: string;
}

export function DomainAnalysis({ fqdn }: DomainAnalysisProps) {
  const { data, isLoading, error } = useDomainAnalysis(fqdn);

  if (data === undefined && isLoading) {
    return <Loading />;
  }

  if (error) {
    toaster.create({
      id: "domain-analysis",
      title: `Error loading domain analysis for: ${fqdn}`,
      description: error.message,
      type: "error",
    });
    return null;
  }

  const color = riskColor(data?.summary.dangerousness_score.value);

  return (
    <Box>
      <VStack gap={2} alignItems="start">
        <HStack gap={3} alignItems="start">
          <Box>
            <Tooltip content={`Risk: ${data?.summary.dangerousness_score.severity_label}`}>
              <ProgressCircle.Root value={data?.summary.dangerousness_score.value} size="lg">
                <ProgressCircle.Circle>
                  <ProgressCircle.Track />
                  <ProgressCircle.Range stroke={color} />
                </ProgressCircle.Circle>
                <AbsoluteCenter>
                  <ProgressCircle.ValueText />
                </AbsoluteCenter>
              </ProgressCircle.Root>
            </Tooltip>
          </Box>
          Categories:
          <Wrap>
            <For each={data?.threat_categorization}>
              {(elem) => <Badge colorPalette="blue">{elem}</Badge>}
            </For>
          </Wrap>
        </HStack>

        <Text>{data?.summary.verdict_reasoning}</Text>

        <Field.Root orientation="horizontal" alignItems="start">
          <Field.Label width={10}>Ad-tech</Field.Label>
          {data?.evidence_assessment.adtech.details}
        </Field.Root>

        <Field.Root orientation="horizontal" alignItems="start">
          <Field.Label width={10}>Personal Data Mining</Field.Label>
          {data?.evidence_assessment.personal_data_mining.details}
        </Field.Root>

        <Field.Root orientation="horizontal" alignItems="start">
          <Field.Label width={10}>Malware Distribution</Field.Label>
          {data?.evidence_assessment.malware_distribution.details}
        </Field.Root>
      </VStack>

      <Heading size="md" pt={2}>
        Recommendations
      </Heading>
      <Container>
        <List.Root>
          <List.Item>{data?.blocklist_recommendations.malware_security_lists.notes}</List.Item>
          <List.Item>
            {data?.blocklist_recommendations.privacy_adblock_dns_sinkholes.notes}
          </List.Item>
        </List.Root>
      </Container>
    </Box>
  );
}
