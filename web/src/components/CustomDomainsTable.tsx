import { useEffect, useRef, useState } from "react";
import {
  Button,
  EmptyState,
  For,
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
import { Loading } from "./Loading";
import { toaster } from "./ui/toaster";

interface CustomDomainRowProps {
  rank: number;
  domain: string;
  filterText?: string;
  onDelete: (domain: string) => void;
}

function CustomDomainRow({ rank, domain, filterText, onDelete }: CustomDomainRowProps) {
  return (
    <Table.Row>
      <Table.Cell>{rank}</Table.Cell>
      <Table.Cell>
        <DomainLink fqdn={domain} highlight={filterText} />
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
      <Table.Cell colSpan={2}>
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

interface CustomDomainsTableProps {
  filterText: string;
}

export function CustomDomainsTable({ filterText }: CustomDomainsTableProps) {
  const { data, isLoading, error } = useCustomDomains();
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
    return <Loading />;
  }

  if (error) {
    toaster.create({
      id: "custom-domains",
      title: "Error loading custom domains",
      description: error.message,
      type: "error",
    });
    return null;
  }

  const domains = data ?? [];

  return (
    <Table.ScrollArea height="calc(100vh - 160px)">
      <Table.Root size="sm">
        <Table.Header>
          <Table.Row>
            <Table.ColumnHeader width={65}>#</Table.ColumnHeader>
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
          <For
            each={domains.toSorted().map((domain, index) => ({ rank: index + 1, domain }))}
            fallback={
              <Table.Row>
                <Table.Cell colSpan={3}>
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
            }
          >
            {({ rank, domain }) => (
              <CustomDomainRow
                key={domain}
                rank={rank}
                domain={domain}
                onDelete={handleDelete}
                filterText={filterText}
              />
            )}
          </For>

          {addingNew && <NewDomainRow onAdd={handleAddNew} onCancel={() => setAddingNew(false)} />}
        </Table.Body>
      </Table.Root>
    </Table.ScrollArea>
  );
}
