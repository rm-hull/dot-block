import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toaster } from "@/components/ui/toaster";
import { type Action, type BlocklistStatus, blocklistAction } from "@/service/blocklists";

export function useBlocklistAction(
  action: Action,
  name?: string,
  payload?: Record<string, unknown>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () => blocklistAction(action, name, payload),
    onSuccess: (data) => {
      queryClient.setQueryData<BlocklistStatus>(["blocklists"], data);
      let title = data.message;
      if (name !== undefined) {
        title += ` (${name})`;
      }
      toaster.create({
        id: "blocklist-action",
        title,
        description: "Action completed successfully.",
        type: "success",
      });
    },
  });
}
