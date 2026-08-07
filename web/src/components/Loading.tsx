import { Progress } from "@chakra-ui/react";

export function Loading() {
  return (
    <Progress.Root
      maxW="100%"
      size="xs"
      variant="subtle"
      value={null}
      colorPalette="blue"
      aria-label="Loading"
    >
      <Progress.Track>
        <Progress.Range />
      </Progress.Track>
    </Progress.Root>
  );
}
