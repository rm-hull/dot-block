import { useQuery } from "@tanstack/react-query";
import { fetchWhoAmI } from "@/service/whoami";

export function useAvatar() {
  return useQuery({
    queryKey: ["whoami"],
    queryFn: fetchWhoAmI,
    retry: false,
  });
}
