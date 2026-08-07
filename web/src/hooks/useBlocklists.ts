import { useQuery } from "@tanstack/react-query";
import { fetchBlocklists } from "@/service/blocklists";

const PERIODIC_REFRESH_INTERVAL_MS = 60_000;

function getNextRefreshDelay(blocklists?: Array<{ disabled_until?: Date | string }>) {
  if (!blocklists?.length) {
    return false;
  }

  const nextRefreshAt = blocklists.reduce<Date | null>((earliest, blocklist) => {
    if (!blocklist.disabled_until) {
      return earliest;
    }

    const disabledUntil = new Date(blocklist.disabled_until);
    if (Number.isNaN(disabledUntil.getTime())) {
      return earliest;
    }

    if (!earliest || disabledUntil.getTime() < earliest.getTime()) {
      return disabledUntil;
    }

    return earliest;
  }, null);

  if (!nextRefreshAt) {
    return false;
  }

  const delay = nextRefreshAt.getTime() - Date.now();
  return delay > 0 ? delay : false;
}

export function useBlocklists() {
  return useQuery({
    queryKey: ["blocklists"],
    queryFn: fetchBlocklists,
    refetchInterval: (query) => {
      const expiryDelay = getNextRefreshDelay(query.state.data?.blocklists);
      if (expiryDelay === false) {
        return PERIODIC_REFRESH_INTERVAL_MS;
      }

      return Math.min(PERIODIC_REFRESH_INTERVAL_MS, expiryDelay);
    },
  });
}
