import { useQuery } from "@tanstack/react-query";
import { fetchDomainAnalysis } from "@/service/net-intent";

export function useDomainAnalysis(fqdn: string) {
  return useQuery({
    queryKey: ["domain-analysis", fqdn],
    queryFn: () => fetchDomainAnalysis(fqdn),
    staleTime: 84600000,
    retry: false,
  });
}
