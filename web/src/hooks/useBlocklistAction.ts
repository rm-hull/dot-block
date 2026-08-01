import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type Action, type BlocklistStatus, blocklistAction } from "@/service/blocklists";

export function useBlocklistAction(
  action: Action,
  name: string,
  payload?: Record<string, unknown>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () => blocklistAction(action, name, payload),
    onSuccess: (data) => {
      queryClient.setQueryData<BlocklistStatus>(["blocklists"], data);
    },
  });
}
