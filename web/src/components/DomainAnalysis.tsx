import {
  Badge,
  Box,
  Field,
  For,
  Text,
  VStack,
  Wrap,
} from "@chakra-ui/react";
import { toaster } from "@/components/ui/toaster";
import { useDomainAnalysis } from "@/hooks/useDomainAnalysis";
import { Loading } from "./Loading";

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
  return (
    <Box>
      <VStack gap={2}>
        <Text>{data?.summary.verdict_reasoning}</Text>

        <Field.Root orientation="horizontal" alignItems="start">
          <Field.Label width={10}>
            Ad-tech
          </Field.Label>
          {data?.evidence_assessment.adtech.details}
        </Field.Root>

        <Field.Root orientation="horizontal" alignItems="start">
          <Field.Label width={10}>
            Personal Data Mining
          </Field.Label>
          {data?.evidence_assessment.personal_data_mining.details}
        </Field.Root>

        <Field.Root orientation="horizontal" alignItems="start">
          <Field.Label width={10}>
            Malware Distribution
          </Field.Label>
          {data?.evidence_assessment.malware_distribution.details}
        </Field.Root>
      </VStack>

      <Wrap pt={2}>
        <For each={data?.threat_categorization}>
          {(elem) => <Badge colorPalette="orange">{elem}</Badge>}
        </For>
      </Wrap>
    </Box>
  );
}
