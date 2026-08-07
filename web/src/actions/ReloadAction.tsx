import { IconButton } from "@chakra-ui/react";
import { LiaHourglassHalfSolid } from "react-icons/lia";
import { TbReload } from "react-icons/tb";
import { Tooltip } from "@/components/ui/tooltip";
import { useBlocklistAction } from "@/hooks/useBlocklistAction";

interface ReloadActionProps {
  name: string;
}

export function ReloadAction({ name }: ReloadActionProps) {
  const { mutate, isPending } = useBlocklistAction("reload", name);

  return (
    <Tooltip content={`Reload ${name}`}>
      <IconButton
        size="2xs"
        disabled={isPending}
        variant="ghost"
        colorPalette="blue"
        onClick={() => mutate()}
      >
        {isPending ? <LiaHourglassHalfSolid /> : <TbReload />}
      </IconButton>
    </Tooltip>
  );
}
