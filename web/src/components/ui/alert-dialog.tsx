import type { PropsWithChildren } from "react";
import { Button, ButtonGroup, CloseButton, Dialog, Portal } from "@chakra-ui/react";

interface AlertDialogProps {
  title: string;
  description: React.ReactNode | string;
  actionLabel?: string;
  actionColorPalette?: "red" | "blue" | "green" | "gray" | "teal";
  onAction?: () => void;
  isOpen?: boolean;
  onClose?: () => void;
}

export function AlertDialog({
  title,
  description,
  actionLabel = "Confirm",
  actionColorPalette = "red",
  onAction,
  children,
}: PropsWithChildren<AlertDialogProps>) {
  return (
    <Dialog.Root>
      <Dialog.Trigger asChild>{children}</Dialog.Trigger>
      <Portal>
        <Dialog.Backdrop />
        <Dialog.Positioner>
          <Dialog.Content>
            <Dialog.Header>
              <Dialog.Title>{title}</Dialog.Title>
            </Dialog.Header>
            <Dialog.Body>{description}</Dialog.Body>
            <Dialog.Footer>
              <ButtonGroup>
                <Dialog.ActionTrigger asChild>
                  <Button variant="ghost">Cancel</Button>
                </Dialog.ActionTrigger>
                <Dialog.ActionTrigger asChild>
                  <Button colorPalette={actionColorPalette} onClick={onAction}>
                    {actionLabel}
                  </Button>
                </Dialog.ActionTrigger>
              </ButtonGroup>
            </Dialog.Footer>
            <Dialog.CloseTrigger asChild>
              <CloseButton size="sm" />
            </Dialog.CloseTrigger>
          </Dialog.Content>
        </Dialog.Positioner>
      </Portal>
    </Dialog.Root>
  );
}
