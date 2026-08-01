import { Span } from "@chakra-ui/react";
import { IoMdCheckmark } from "react-icons/io";
import { RiErrorWarningLine } from "react-icons/ri";
import { RxCross2 } from "react-icons/rx";
import { useExists } from "@/hooks/useExists";
import { Tooltip } from "./ui/tooltip";

interface FreshSuffixProps {
  url: string;
}

export function FreshSuffix({ url }: FreshSuffixProps) {
  const { exists, isLoading, error } = useExists(url);

  if (isLoading) {
    return null;
  }

  if (error) {
    return (
      <Span color="red.400">
        <Tooltip content={error.message}>
          <RiErrorWarningLine size={16} />
        </Tooltip>
      </Span>
    );
  }

  if (!exists) {
    return (
      <Span color="red.400">
        <Tooltip content="URL is unreachable">
          <RxCross2 size={16} />
        </Tooltip>
      </Span>
    );
  }

  return (
    <Span color="green.400">
      <Tooltip content="URL is reachable">
        <IoMdCheckmark size={16} />
      </Tooltip>
    </Span>
  );
}
