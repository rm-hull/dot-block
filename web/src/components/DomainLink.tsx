import { useState } from "react";
import { CloseButton, Drawer, Highlight, Link, Portal, Tabs } from "@chakra-ui/react";
import { DnsResult } from "./DnsResult";
import { DomainAnalysis } from "./DomainAnalysis";
import { UrlScan } from "./UrlScan";

interface DomainLinkProps {
  fqdn: string;
  highlight?: string;
}

export function DomainLink({ fqdn, highlight }: DomainLinkProps) {
  const [open, setOpen] = useState(false);
  const [selectedFqdn, setSelectedFqdn] = useState(fqdn);

  return (
    <Drawer.Root
      size="md"
      open={open}
      onOpenChange={(details) => {
        setOpen(details.open);
        if (details.open) setSelectedFqdn(fqdn);
      }}
    >
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
              <Drawer.Title>{selectedFqdn}</Drawer.Title>
              <Drawer.CloseTrigger asChild>
                <CloseButton size="sm" />
              </Drawer.CloseTrigger>
            </Drawer.Header>
            <Drawer.Body pt={0}>
              <Tabs.Root defaultValue="analysis">
                <Tabs.List position="sticky" top={0} bg="bg" zIndex={1}>
                  <Tabs.Trigger value="analysis">Threat Analysis</Tabs.Trigger>
                  <Tabs.Trigger value="urlscan">URL Scan</Tabs.Trigger>
                  <Tabs.Trigger value="dns">DNS Results</Tabs.Trigger>
                </Tabs.List>
                <Tabs.Content value="analysis">
                  <DomainAnalysis fqdn={selectedFqdn} />
                </Tabs.Content>
                <Tabs.Content value="urlscan">
                  <UrlScan fqdn={selectedFqdn} />
                </Tabs.Content>
                <Tabs.Content value="dns">
                  <DnsResult fqdn={selectedFqdn} />
                </Tabs.Content>
              </Tabs.Root>
            </Drawer.Body>
          </Drawer.Content>
        </Drawer.Positioner>
      </Portal>
    </Drawer.Root>
  );
}
