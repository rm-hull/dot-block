import { Box, Flex, HStack, Span } from '@chakra-ui/react'
import { RouterLink } from '@/components/ui/router-link'
import { UserAvatar } from './UserAvatar'

export function Navbar() {
  return (
    <Box
      as="nav"
      position="sticky"
      top="0"
      zIndex="sticky"
      bg="bg"
      borderBottom="1px solid"
      borderColor="border"
      px={4}
      py={3}
    >
      <Flex align="center" justify="space-between" maxW="container.xl" mx="auto">
        <HStack gap={6}>
          <RouterLink to="/" fontSize="xl" gap={0}>
            <Span fontWeight="bold">DOT</Span>
            <Span fontWeight="light" color="fg.subtle">block</Span>
          </RouterLink>

          <HStack gap={4} fontSize="sm" color="fg.muted">
            <RouterLink to="/events" activeProps={{ fontWeight: 'semibold', color: 'blue.500' }}>
              Events
            </RouterLink>
            <RouterLink to="/settings" activeProps={{ fontWeight: 'semibold', color: 'blue.500' }}>
              Settings
            </RouterLink>
            <RouterLink to="/about" activeProps={{ fontWeight: 'semibold', color: 'blue.500' }}>
              About
            </RouterLink>
          </HStack>
        </HStack>

        <UserAvatar />
      </Flex>
    </Box>
  )
}
