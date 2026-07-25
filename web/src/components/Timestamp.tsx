import { Span, Text } from "@chakra-ui/react"
import { Tooltip } from "@/components/ui/tooltip"

interface TimestampProps {
  value: Date
}
export function Timestamp({ value }: TimestampProps) {
  const time = value.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
  const ms = value.getMilliseconds().toString().padStart(3, "0")

  return (
    <Tooltip content={value.toISOString()}>
      <Text gap={0} fontFamily="mono" letterSpacing={-1.2}>
        <Span>{time}</Span>
        <Span fontSize="xs" >.{ms}</Span>
      </Text>
    </Tooltip>
  )
}