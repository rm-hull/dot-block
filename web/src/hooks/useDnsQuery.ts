import { useQuery } from "@tanstack/react-query";
import { fetchDnsQuery } from "@/service/dns-query";

export function useDnsQuery(fqdn: string) {
  return useQuery({
    queryKey: ["dns-query", fqdn],
    queryFn: () => fetchDnsQuery(fqdn),
  });
}
