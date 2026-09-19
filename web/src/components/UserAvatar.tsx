import { Avatar } from "@chakra-ui/react";
import { Tooltip } from "@/components/ui/tooltip";
import { useAuth } from "@/hooks/useAuth";
import type { User } from "@/service/auth";

const colorPalette = ["red", "blue", "green", "yellow", "purple", "orange"];

const pickPalette = (name: string) => {
  if (!name) return colorPalette[0];
  const index = name.charCodeAt(0) % colorPalette.length;
  return colorPalette[index];
};

interface UserAvatarProps {
  user: User;
}

export function UserAvatar({ user }: UserAvatarProps) {
  return (
    <Tooltip content={user.email}>
      <Avatar.Root size="sm" colorPalette={pickPalette(user.user)} cursor="pointer">
        <Avatar.Fallback name={user.user} />
        <Avatar.Image src={`https://www.gravatar.com/avatar/${user.emailHash}`} />
      </Avatar.Root>
    </Tooltip>
  );
}
