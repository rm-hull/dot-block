import { useContext, useLayoutEffect, useState } from "react";
import { createPortal } from "react-dom";
import { HStack } from "@chakra-ui/react";
import { ConnectionIcon } from "@/components/ConnectionIcon";
import { EventStreamControls, type Status } from "@/components/EventStreamControls";
import { FilterTextField } from "@/components/FilterTextField";
import { NavbarToolbarContext } from "@/components/Navbar";

interface EventPortalToolbarProps {
  filterText: string;
  onFilterTextChange: (value: string) => void;
  status: Status;
  onStatusChange: (status: Status) => void;
  connected?: boolean;
}

export function EventPortalToolbar({
  filterText,
  onFilterTextChange,
  status,
  onStatusChange,
  connected,
}: EventPortalToolbarProps) {
  const toolbarHostRef = useContext(NavbarToolbarContext);
  const [toolbarHost, setToolbarHost] = useState<HTMLDivElement | null>(null);

  useLayoutEffect(() => {
    setToolbarHost(toolbarHostRef?.current ?? null);
  }, [toolbarHostRef]);

  if (!toolbarHost) {
    return null;
  }

  return createPortal(
    <HStack gap={4}>
      <FilterTextField value={filterText} onValueChange={onFilterTextChange} />
      <EventStreamControls connected={connected} status={status} onStatusChange={onStatusChange} />
      <ConnectionIcon connected={connected} active={status === "active"} />
    </HStack>,
    toolbarHost
  );
}
