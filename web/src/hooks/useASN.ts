import { fetchASN, type ASN } from "@/service/asn";
import { useQuery } from "@tanstack/react-query";

export function useASN(ipAddr: string) {
  return useQuery<ASN | null>({
    queryKey: ["asn", ipAddr],
    queryFn: () => fetchASN(ipAddr),
    staleTime: 84600000,
    retry: false,
  });
}
