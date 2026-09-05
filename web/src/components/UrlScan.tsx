import { Field, Image, Link, VStack } from "@chakra-ui/react";
import ReactTimeAgo from "react-time-ago";
import { toaster } from "@/components/ui/toaster";
import { useUrlScan } from "@/hooks/useUrlScan";
import { isError } from "@/types/net-intent/url-scan";
import { ASN } from "./ASN";
import { Loading } from "./Loading";

interface UrlScanProps {
  fqdn: string;
}

export function UrlScan({ fqdn }: UrlScanProps) {
  const { data, isLoading, error } = useUrlScan(fqdn);

  if (data === undefined && isLoading) {
    return <Loading />;
  }

  if (error) {
    toaster.create({
      id: "url-scan",
      title: `Error loading URL scan results for: ${fqdn}`,
      description: error.message,
      type: "error",
    });
    return null;
  }

  if (isError(data)) {
    return <VStack>{data.error}</VStack>;
  }

  return (
    <VStack gap={1}>
      {data?.page.ip && (
        <Field.Root orientation="horizontal">
          <Field.Label flex={1}>ASN</Field.Label>
          <ASN ipAddr={data?.page.ip} />
        </Field.Root>
      )}

      <Field.Root orientation="horizontal">
        <Field.Label flex={1}>IP</Field.Label>
        {data?.page.ip}
      </Field.Root>

      {data?.page.apexDomain && (
        <Field.Root orientation="horizontal">
          <Field.Label flex={1}>Apex domain</Field.Label>
          <Link href={"//" + data?.page.apexDomain} target="_blank">
            {data?.page.apexDomain}
          </Link>
        </Field.Root>
      )}

      {(data?.page.domainAgeDays ?? 0) > 0 && (
        <Field.Root orientation="horizontal">
          <Field.Label flex={1}>Domain age</Field.Label>
          {data?.page.domainAgeDays} days
        </Field.Root>
      )}

      {data?.page.tlsIssuer && (
        <Field.Root orientation="horizontal">
          <Field.Label flex={1}>TLS issuer</Field.Label>
          {data?.page.tlsIssuer}
        </Field.Root>
      )}

      {(data?.page.tlsValidDays ?? 0) > 0 && data?.page.tlsValidFrom && (
        <Field.Root orientation="horizontal">
          <Field.Label flex={1}>TLS created</Field.Label>
          <ReactTimeAgo date={data?.page.tlsValidFrom} />
        </Field.Root>
      )}

      {(data?.page.umbrellaRank ?? 0) > 0 && (
        <Field.Root orientation="horizontal">
          <Field.Label flex={1}>Umbrella rank</Field.Label>
          {data?.page.umbrellaRank}
        </Field.Root>
      )}

      <Image
        border={0.5}
        borderRadius={5}
        borderColor="fg.subtle"
        borderStyle="solid"
        src={data?.screenshot}
        alt="screenshot"
        objectFit="cover"
      />
    </VStack>
  );
}
