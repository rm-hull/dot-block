import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toaster } from "@/components/ui/toaster";
import { addCustomDomains, fetchCustomDomains, removeCustomDomains } from "@/service/customDomains";

const CUSTOM_DOMAINS_REFRESH_INTERVAL_MS = 30_000;

export function useCustomDomains() {
  return useQuery({
    queryKey: ["customDomains"],
    queryFn: fetchCustomDomains,
    refetchInterval: CUSTOM_DOMAINS_REFRESH_INTERVAL_MS,
  });
}

export function useAddCustomDomains() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: addCustomDomains,
    onSuccess: (data) => {
      queryClient.setQueryData<string[]>(["customDomains"], data.domains ?? []);
      toaster.create({
        id: "add-custom-domains",
        title: "Custom Blocklist",
        description: data.message ?? "Successfully added domain(s) to the custom blocklist.",
        type: "success",
      });
    },
    onError: (error: Error) => {
      toaster.create({
        id: "add-custom-domains",
        title: "Custom Blocklist",
        description: error.message,
        type: "error",
      });
    },
  });
}

export function useRemoveCustomDomains() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: removeCustomDomains,
    onSuccess: (data) => {
      queryClient.setQueryData<string[]>(["customDomains"], data.domains ?? []);
      toaster.create({
        id: "remove-custom-domains",
        title: "Custom Blocklist",
        description: data.message ?? "Successfully removed domain(s) from the custom blocklist.",
        type: "success",
      });
    },
    onError: (error: Error) => {
      toaster.create({
        id: "remove-custom-domains",
        title: "Custom Blocklist",
        description: error.message,
        type: "error",
      });
    },
  });
}
