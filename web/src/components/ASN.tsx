import { useASN } from "@/hooks/useASN"
import { Badge, HStack, Skeleton } from "@chakra-ui/react"
import { Flag } from "./Flag";

interface ASNProps {
  ipAddr: string
};

export function ASN({ ipAddr }: ASNProps) {
  const { data, isLoading, error } = useASN(ipAddr)

  if (error) {
    return <div>{error.toString()}</div>; // TODO:
  }
  return (
    <Skeleton asChild loading={isLoading} width={200}>
      <HStack>
        <Badge colorPalette="blue">{data?.asn}: {data?.provider}</Badge>
        <Flag isoCode={data?.iso_code} width={20} />
      </HStack>
    </Skeleton>
  )
}