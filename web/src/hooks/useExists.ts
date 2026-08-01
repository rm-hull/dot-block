import { useQuery } from "@tanstack/react-query";

export function useExists(url: string) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["exists", url],
    queryFn: async () => {
      const response = await fetch(url, { method: "HEAD" });
      return response.ok;
    },
    staleTime: 3600000, // 1 hour
  });

  return {
    exists: data,
    isLoading,
    error,
  };
}
