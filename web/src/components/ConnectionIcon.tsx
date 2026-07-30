import { Box } from "@chakra-ui/react";
import { Tooltip } from "./ui/tooltip";
import { TbCloudDataConnection } from "react-icons/tb";
import styles from "./ConnectionIcon.module.css";

interface ConnectionIconProps {
  connected?: boolean
  active: boolean
}

export function ConnectionIcon({ connected, active }: ConnectionIconProps) {
  return (
    <Tooltip content={connected ? "Connected" : "Not connected"}>
      <Box
        className={connected && active ? styles.pulseIcon : styles.blinkIcon}
        color={connected ? "green" : "fg.subtle"}>
        <TbCloudDataConnection size={24} />
      </Box>
    </Tooltip>
  );
}