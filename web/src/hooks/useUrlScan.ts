import { useQuery } from "@tanstack/react-query";
import { fetchUrlScan } from "@/service/net-intent";

export function useUrlScan(fqdn: string) {
  return useQuery({
    queryKey: ["url-scan", fqdn],
    queryFn: () => fetchUrlScan(fqdn),
    staleTime: 84600000,
    retry: false,
  });
}
