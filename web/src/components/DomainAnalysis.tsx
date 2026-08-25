import { Badge, Box, Code, For, HStack, Heading, Text } from "@chakra-ui/react";
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
      <HStack>
        <For each={data?.threat_categorization}>
          {(elem) => <Badge colorPalette="orange">{elem}</Badge>}
        </For>
      </HStack>
      <Text>{data?.summary.verdict_reasoning}</Text>

      <Heading size="sm">Ad-tech</Heading>
      <Text>{data?.evidence_assessment.adtech.details}</Text>

      <Heading size="sm">Personal Data Mining</Heading>
      <Text>{data?.evidence_assessment.personal_data_mining.details}</Text>

      <Heading size="sm">Malware Distribution</Heading>
      <Text>{data?.evidence_assessment.malware_distribution.details}</Text>

      <Code>
        <pre>{JSON.stringify(data, null, 2)}</pre>
      </Code>
    </Box>
  );
}
