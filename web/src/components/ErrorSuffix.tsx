import { Span } from "@chakra-ui/react";
import { IoMdCheckmark } from "react-icons/io";
import { RiErrorWarningLine } from "react-icons/ri";
import { Tooltip } from "./ui/tooltip";

interface ErrorSuffixProps {
  error?: string;
}

export function ErrorSuffix({ error }: ErrorSuffixProps) {
  if (error) {
    return (
      <Span color="red.400">
        <Tooltip content={error}>
          <RiErrorWarningLine size={16} />
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
