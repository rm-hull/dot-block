import { CloseButton, Drawer, Highlight, Link, Portal, Tabs } from "@chakra-ui/react";
import { DomainAnalysis } from "./DomainAnalysis";
import { UrlScan } from "./UrlScan";

interface DomainLinkProps {
  fqdn: string;
  highlight?: string;
}

export function DomainLink({ fqdn, highlight }: DomainLinkProps) {
  return (
    <Drawer.Root size="md">
      <Drawer.Trigger asChild>
        <Link gap={0}>
          <Highlight query={highlight ?? ""} styles={{ bg: "yellow.subtle", color: "yellow.fg" }}>
            {fqdn}
          </Highlight>
        </Link>
      </Drawer.Trigger>
      <Portal>
        <Drawer.Backdrop />
        <Drawer.Positioner>
          <Drawer.Content>
            <Drawer.Header position="sticky" top={0} bg="bg" zIndex={2}>
              <Drawer.Title>{fqdn}</Drawer.Title>
              <Drawer.CloseTrigger asChild>
                <CloseButton size="sm" />
              </Drawer.CloseTrigger>
            </Drawer.Header>
            <Drawer.Body pt={0}>
              <Tabs.Root defaultValue="analysis">
                <Tabs.List position="sticky" top={0} bg="bg" zIndex={1}>
                  <Tabs.Trigger value="analysis">Threat Analysis</Tabs.Trigger>
                  <Tabs.Trigger value="urlscan">URL Scan</Tabs.Trigger>
                </Tabs.List>
                <Tabs.Content value="analysis">
                  <DomainAnalysis fqdn={fqdn} />
                </Tabs.Content>
                <Tabs.Content value="urlscan">
                  <UrlScan fqdn={fqdn} />
                </Tabs.Content>
              </Tabs.Root>
            </Drawer.Body>
          </Drawer.Content>
        </Drawer.Positioner>
      </Portal>
    </Drawer.Root>
  );
}
