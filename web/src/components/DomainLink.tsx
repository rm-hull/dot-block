import { CloseButton, Drawer, Highlight, Link, Portal } from "@chakra-ui/react";
import { DomainAnalysis } from "./DomainAnalysis";

interface DomainLinkProps {
  fqdn: string;
  highlight?: string;
}

export function DomainLink({ fqdn, highlight }: DomainLinkProps) {
  return (
    <Drawer.Root size="md">
      <Drawer.Trigger asChild>
        <Link>
          <Highlight query={highlight ?? ""} styles={{ bg: "yellow.subtle", color: "yellow.fg" }}>
            {fqdn}
          </Highlight>
        </Link>
      </Drawer.Trigger>
      <Portal>
        <Drawer.Backdrop />
        <Drawer.Positioner>
          <Drawer.Content>
            <Drawer.Header>
              <Drawer.Title>{fqdn}</Drawer.Title>
            </Drawer.Header>
            <Drawer.Body>
              <DomainAnalysis fqdn={fqdn} />
            </Drawer.Body>
            <Drawer.CloseTrigger asChild>
              <CloseButton size="sm" />
            </Drawer.CloseTrigger>
          </Drawer.Content>
        </Drawer.Positioner>
      </Portal>
    </Drawer.Root>
  );
}
