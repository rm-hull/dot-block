import { Container } from '@chakra-ui/react'
import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/events')({
  component: () => <Container>TODO: Events</Container>
})
