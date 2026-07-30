import { createFileRoute } from "@tanstack/react-router";
import { Container } from "@chakra-ui/react";

export const Route = createFileRoute("/settings")({
  component: () => <Container>TODO: Settings</Container>,
});
