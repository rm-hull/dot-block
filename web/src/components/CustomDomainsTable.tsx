import { useEffect, useRef, useState } from "react";
import {
  Button,
  EmptyState,
  HStack,
  IconButton,
  Input,
  Strong,
  Table,
  Text,
} from "@chakra-ui/react";
import { FiPlus, FiTrash2 } from "react-icons/fi";
import { DomainLink } from "@/components/DomainLink";
import { AlertDialog } from "@/components/ui/alert-dialog";
import {
  useAddCustomDomains,
  useCustomDomains,
  useRemoveCustomDomains,
} from "@/hooks/useCustomDomains";

function CustomDomainRow({
  domain,
  onDelete,
}: {
  domain: string;
  onDelete: (domain: string) => void;
}) {
  return (
    <Table.Row>
      <Table.Cell>
        <DomainLink fqdn={domain} />
      </Table.Cell>
      <Table.Cell textAlign="right">
        <AlertDialog
          title="Remove Domain"
          description={
            <Text>
              Are you sure you want to remove <Strong>"{domain}"</Strong> from the custom blocklist?
            </Text>
          }
          actionLabel="Remove"
          actionColorPalette="red"
          onAction={() => onDelete(domain)}
        >
          <IconButton aria-label="Delete domain" size="2xs" variant="ghost" colorPalette="red">
            <FiTrash2 />
          </IconButton>
        </AlertDialog>
      </Table.Cell>
    </Table.Row>
  );
}

function NewDomainRow({
  onAdd,
  onCancel,
}: {
  onAdd: (domain: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleAdd = () => {
    const trimmed = value.trim();
    if (trimmed) {
      onAdd(trimmed);
      setValue("");
    } else {
      onCancel();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      handleAdd();
    } else if (e.key === "Escape") {
      onCancel();
    }
  };

  const handleBlur = () => {
    if (!value.trim()) {
      onCancel();
    }
  };

  return (
    <Table.Row>
      <Table.Cell>
        <Input
          ref={inputRef}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={handleKeyDown}
          onBlur={handleBlur}
          placeholder="Enter a domain to add..."
          size="xs"
          border={0}
          focusRing="none"
          p={0}
        />
      </Table.Cell>
      <Table.Cell textAlign="right">
        <IconButton
          aria-label="Add domain"
          size="2xs"
          variant="ghost"
          onClick={handleAdd}
          disabled={!value.trim()}
        >
          <FiPlus />
        </IconButton>
      </Table.Cell>
    </Table.Row>
  );
}

export function CustomDomainsTable() {
  const { data: domains, isLoading, error } = useCustomDomains();
  const removeMutation = useRemoveCustomDomains();
  const addMutation = useAddCustomDomains();
  const [addingNew, setAddingNew] = useState(false);

  const handleDelete = (domain: string) => {
    removeMutation.mutate([domain]);
  };

  const handleAddNew = (domain: string) => {
    addMutation.mutate([domain]);
    setAddingNew(false);
  };

  const handleAddButtonClick = () => {
    setAddingNew(!addingNew);
  };

  if (isLoading) {
    return <Text>Loading custom domains...</Text>;
  }

  if (error) {
    return <Text color="red.500">Error loading custom domains:{(error as Error)?.message}</Text>;
  }

  const domainList = domains ?? [];

  return (
    <Table.ScrollArea height="calc(100vh - 160px)">
      <Table.Root size="sm">
        <Table.Header>
          <Table.Row>
            <Table.ColumnHeader>Domain</Table.ColumnHeader>
            <Table.ColumnHeader width="100px" textAlign="right">
              <Button size="2xs" onClick={handleAddButtonClick}>
                <HStack gap={1}>
                  <FiPlus />
                  <Text>Add</Text>
                </HStack>
              </Button>
            </Table.ColumnHeader>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {domainList.length === 0 ? (
            <Table.Row>
              <Table.Cell colSpan={2}>
                <EmptyState.Root>
                  <EmptyState.Content>
                    <EmptyState.Title>No custom domains</EmptyState.Title>
                    <EmptyState.Description>
                      Add domains to the custom blocklist using the "Add" button above.
                    </EmptyState.Description>
                  </EmptyState.Content>
                </EmptyState.Root>
              </Table.Cell>
            </Table.Row>
          ) : (
            domainList
              .toSorted()
              .map((domain) => (
                <CustomDomainRow key={domain} domain={domain} onDelete={handleDelete} />
              ))
          )}

          {addingNew && <NewDomainRow onAdd={handleAddNew} onCancel={() => setAddingNew(false)} />}
        </Table.Body>
      </Table.Root>
    </Table.ScrollArea>
  );
}
