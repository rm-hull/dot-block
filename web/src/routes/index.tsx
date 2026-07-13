import { Box, Container, Heading, VStack } from "@chakra-ui/react"
import { createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/")({
  component: HomePage,
})

function HomePage() {
  return (
    <Container>
      <Heading>Coming soon!</Heading>
      <VStack alignItems="start" gap={0}>
        <Box>Version: {import.meta.env.VITE_GIT_COMMIT_HASH}</Box>
        <Box>Date: {import.meta.env.VITE_GIT_COMMIT_DATE}</Box>
      </VStack>
    </Container>
  )
}