import { createLink } from '@tanstack/react-router'
import { Link as ChakraLink } from '@chakra-ui/react'
import { forwardRef, type ComponentPropsWithoutRef } from 'react'

export const RouterLink = createLink(
  forwardRef<HTMLAnchorElement, ComponentPropsWithoutRef<typeof ChakraLink>>((props, ref) => {
    return <ChakraLink ref={ref} {...props} />
  }),
)
