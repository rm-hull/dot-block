import { Skeleton, Stat } from "@chakra-ui/react";
interface PercentageStatProps {
  title: string
  value?: number
  total?: number
  digits?: number
  helpText?: string
}

export function PercentageStat({ title, value, total, digits = 1, helpText }: PercentageStatProps) {

  return (
    <Stat.Root>
      <Stat.Label>{title}</Stat.Label>
      <Stat.ValueText alignItems="baseline">
        {(total ?? 0) > 0 ? ((value ?? 0) * 100 / (total ?? 1)).toFixed(digits) : <Skeleton height="28px" width="50px" />} <Stat.ValueUnit>%</Stat.ValueUnit>
      </Stat.ValueText>
      <Stat.HelpText>{helpText}</Stat.HelpText>
    </Stat.Root>
  )
}