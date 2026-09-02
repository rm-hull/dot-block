import { Badge } from "@chakra-ui/react";
import { Tooltip } from "@/components/ui/tooltip";

export const statusFlags = ["TC", "RD", "RA", "AD", "CD"] as const;
export type StatusFlagType = (typeof statusFlags)[number];

const mapping: Record<StatusFlagType, { descr: string }> = {
  TC: { descr: "Response was truncated" },
  RD: { descr: "Recursion was desired" },
  RA: { descr: "Recursion is available" },
  AD: { descr: "All answers were authenticated" },
  CD: { descr: "Checking disabled" },
};

interface StatusFlagProps {
  flag: StatusFlagType;
  disabled?: boolean;
}

export function StatusFlag({ flag, disabled }: StatusFlagProps) {
  const descr = mapping[flag].descr;

  return (
    <Tooltip content={descr} disabled={disabled}>
      <Badge
        colorPalette={disabled ? "grey" : "blue"}
        variant={disabled ? "outline" : undefined}
        cursor={disabled ? "disabled" : undefined}
      >
        {flag}
      </Badge>
    </Tooltip>
  );
}
