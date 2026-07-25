import { fetchWhoAmI } from "@/service/whoami";
import { useQuery } from "@tanstack/react-query";

export function useAvatar() {
  return  useQuery({
    queryKey: ['whoami'],
    queryFn: fetchWhoAmI,
    retry: false,
  })
}