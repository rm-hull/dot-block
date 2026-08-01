import { Switch } from "@chakra-ui/react";
import { HiCheck, HiX } from "react-icons/hi";
import { Tooltip } from "@/components/ui/tooltip";
import { useBlocklistAction } from "@/hooks/useBlocklistAction";

interface ActiveActionProps {
  name: string;
  active: boolean;
}

const DISABLE_MINS = 5;
const DISABLE_DURATION = `PT${DISABLE_MINS}M`; // 5 minutes

export function ActiveAction({ name, active }: ActiveActionProps) {
  const { mutate: disable, isPending: isDisablePending } = useBlocklistAction("disable", name, {
    duration: DISABLE_DURATION,
  });
  const { mutate: reenable, isPending: isReenablePending } = useBlocklistAction("reenable", name);

  const handleActiveChange = (checked: boolean) => {
    if (checked) {
      reenable();
    } else {
      disable();
    }
  };

  return (
    <Tooltip
      content={active ? `Click to disable for ${DISABLE_MINS} minutes` : "Click to re-enable"}
    >
      <Switch.Root
        colorPalette="green"
        size="lg"
        checked={active}
        disabled={isDisablePending || isReenablePending}
        onCheckedChange={(e) => handleActiveChange(e.checked)}
      >
        <Switch.HiddenInput />
        <Switch.Control>
          <Switch.Thumb>
            <Switch.ThumbIndicator fallback={<HiX color="red" />}>
              <HiCheck />
            </Switch.ThumbIndicator>
          </Switch.Thumb>
        </Switch.Control>
        <Switch.Label />
      </Switch.Root>
    </Tooltip>
  );
}
