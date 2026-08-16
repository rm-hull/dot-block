import { useContext, useLayoutEffect, useState } from "react";
import { createPortal } from "react-dom";
import { HStack, Text } from "@chakra-ui/react";
import { ActiveAction } from "@/actions/ActiveAction";
import { NavbarToolbarContext } from "@/components/Navbar";

interface GlobalKillSwitchProps {
  active: boolean;
}

export function GlobalKillSwitch({ active }: GlobalKillSwitchProps) {
  const killSwitchRef = useContext(NavbarToolbarContext);
  const [killSwitch, setkillSwitch] = useState<HTMLDivElement | null>(null);

  useLayoutEffect(() => {
    setkillSwitch(killSwitchRef?.current ?? null);
  }, [killSwitchRef]);

  if (!killSwitch) {
    return null;
  }

  return createPortal(
    <HStack gap={4}>
      <Text fontSize="sm" color="fg.muted">
        Global kill-switch:
      </Text>
      <ActiveAction active={active} />
    </HStack>,
    killSwitch
  );
}
