import { Box } from "@chakra-ui/react";
import { TbCloudDataConnection } from "react-icons/tb";
import { Tooltip } from "./ui/tooltip";
import styles from "./EventToolbar.module.css";

interface EventToolbarProps {
  connected?: boolean
}

export function EventToolbar({ connected }: EventToolbarProps) {
  return (
    <>
      <Tooltip content={connected ? "Connected" : "Not connected"}>
        <Box className={connected ? styles.pulseIcon : styles.blinkIcon}>
          <TbCloudDataConnection size={24} color={connected ? "green" : "grey.300"} />
        </Box>
      </Tooltip>
    </>
  )
}