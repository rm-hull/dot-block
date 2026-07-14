import { useASN } from "@/hooks/useASN"
import { Badge, Skeleton } from "@chakra-ui/react"

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
      <Badge>{data?.asn}: {data?.provider}</Badge>
    </Skeleton>
  )
}