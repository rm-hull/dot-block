import { Box, Container, VStack } from '@chakra-ui/react'
import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/about')({
  component: () =>
    <Container>
      <VStack alignItems="start" gap={0}>
        <Box>Version: {import.meta.env.VITE_GIT_COMMIT_HASH}</Box>
        <Box>Date: {import.meta.env.VITE_GIT_COMMIT_DATE}</Box>
      </VStack>
    </Container>
})
