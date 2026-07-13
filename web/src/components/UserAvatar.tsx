import { fetchWhoAmI } from '@/service/whoami'
import { Avatar } from '@chakra-ui/react'
import { useQuery } from '@tanstack/react-query'

const colorPalette = ["red", "blue", "green", "yellow", "purple", "orange"]

const pickPalette = (name: string) => {
  const index = name.charCodeAt(0) % colorPalette.length
  return colorPalette[index]
}

export function UserAvatar() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['whoami'],
    queryFn: fetchWhoAmI,
  })

  console.log({ data })
  if (isLoading || error || !data) {
    return null;
  }

  const gravatarUrl = `https://www.gravatar.com/avatar/${encodeURIComponent(
    data.email.trim().toLowerCase()
  )}`

  return (
    <Avatar.Root size="sm" colorPalette={pickPalette(data.user)}>
      <Avatar.Fallback name={data.user} />
      <Avatar.Image src={gravatarUrl} />
    </Avatar.Root>
  )
}
