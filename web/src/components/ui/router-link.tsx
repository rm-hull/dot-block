import { createLink } from '@tanstack/react-router'
import { Link as ChakraLink } from '@chakra-ui/react'
import { forwardRef } from 'react'

export const RouterLink = createLink(
  forwardRef<HTMLAnchorElement, Record<string, unknown>>((props, ref) => {
    return <ChakraLink ref={ref} {...props} />
  }),
)
