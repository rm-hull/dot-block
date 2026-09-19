import { useQuery } from "@tanstack/react-query";
import { fetchWhoAmI } from "@/service/auth";

export function useAuth() {
  return useQuery({
    queryKey: ["auth"],
    queryFn: fetchWhoAmI,
    retry: false,
  });
}
