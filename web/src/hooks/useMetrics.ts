import { useQuery } from "@tanstack/react-query";
import { fetchMetrics } from "@/service/metrics";

export function useMetrics() {
  return useQuery({
    queryKey: ["metrics"],
    queryFn: fetchMetrics,
    refetchInterval: 30_000,
  });
}
