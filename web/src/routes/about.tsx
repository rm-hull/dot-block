import { ASN } from '@/components/ASN'
import { Flag } from '@/components/Flag'
import { Box, Container, VStack } from '@chakra-ui/react'
import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/about')({
  component: () =>
    <Container>
      <VStack alignItems="start" gap={0}>
        <Box>Version: {import.meta.env.VITE_GIT_COMMIT_HASH}</Box>
        <Box>Date: {import.meta.env.VITE_GIT_COMMIT_DATE}</Box>
        <Flag isoCode='AU' />
        <ASN ipAddr='123.4.89.4' />
        <ASN ipAddr='24.123.12.0' />
      </VStack>
    </Container>
})
