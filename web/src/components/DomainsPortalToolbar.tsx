import { useContext, useLayoutEffect, useState } from "react";
import { createPortal } from "react-dom";
import { HStack } from "@chakra-ui/react";
import { ConnectionIcon } from "@/components/ConnectionIcon";
import { EventStreamControls, type Status } from "@/components/EventStreamControls";
import { FilterTextField } from "@/components/FilterTextField";
import { NavbarToolbarContext } from "@/components/Navbar";

interface DomainsPortalToolbarProps {
  filterText: string;
  onFilterTextChange: (value: string) => void;
}

export function DomainsPortalToolbar({
  filterText,
  onFilterTextChange,
}: DomainsPortalToolbarProps) {
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
    </HStack>,
    toolbarHost
  );
}
