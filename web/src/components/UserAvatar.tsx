import { Avatar } from '@chakra-ui/react'
import { Tooltip } from '@/components/ui/tooltip'
import { useAvatar } from '@/hooks/useAvatar'

const colorPalette = ["red", "blue", "green", "yellow", "purple", "orange"]

const pickPalette = (name: string) => {
  if (!name) return colorPalette[0]
  const index = name.charCodeAt(0) % colorPalette.length
  return colorPalette[index]
}

export function UserAvatar() {
  const { data, isLoading, error } = useAvatar();
  if (isLoading || error || !data) {
    return null;
  }

  return (
    <Tooltip content={data.email}>
      <Avatar.Root size="sm" colorPalette={pickPalette(data.user)} cursor="pointer">
        <Avatar.Fallback name={data.user} />
        <Avatar.Image src={`https://www.gravatar.com/avatar/${data.emailHash}`} />
      </Avatar.Root>
    </Tooltip>
  )
}
