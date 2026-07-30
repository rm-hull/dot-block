import { HStack, IconButton } from "@chakra-ui/react";
import { Tooltip } from "./ui/tooltip";
import { IoPlayOutline, IoPauseOutline } from "react-icons/io5";

export type Status = "paused" | "active"

interface EventToolbarProps {
  connected?: boolean
  status: Status
  onStatusChange(status: Status): void
}

export function EventToolbar({ connected, status, onStatusChange }: EventToolbarProps) {
  const active = status === "active"
  const handleClick = (nextStatus: Status) => () => {
    onStatusChange(nextStatus)
  }

  return (
    <HStack gap={1}>
      <IconButton variant="outline" disabled={active || !connected} size="2xs" color="blue.400" onClick={handleClick("active")}>
        <Tooltip content="Play">
          <IoPlayOutline />
        </Tooltip>
      </IconButton >

      <IconButton variant="outline" disabled={!active || !connected} size="2xs" color="red.400" onClick={handleClick("paused")}>
        <Tooltip content="Pause">
          <IoPauseOutline />
        </Tooltip>
      </IconButton >
    </HStack>
  )
}