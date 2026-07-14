import * as Flags from 'country-flag-icons/react/3x2'
import countries from 'i18n-iso-countries'
import enLocale from 'i18n-iso-countries/langs/en.json';
import { Tooltip } from './ui/tooltip';

interface FlagProps {
  isoCode?: keyof typeof Flags
  width?: number
}

countries.registerLocale(enLocale);

export function Flag({ isoCode, width = 32 }: FlagProps) {

  if (!isoCode) {
    return null;
  }
  const FlagComponent = Flags[isoCode]
  if (!FlagComponent) {
    return null
  }

  return (
    <Tooltip content={`${countries.getName(isoCode, "en")} (${isoCode})`}>
      <FlagComponent width={width} />
    </Tooltip>
  )
}