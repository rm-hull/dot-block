import { useRef } from "react";
import { CloseButton, Input, InputGroup } from "@chakra-ui/react";
import { LuSearch } from "react-icons/lu";
import { useKey } from "react-use";

interface FilterTextFieldProps {
  value: string;
  onValueChange(value: string): void;
}

export function FilterTextField({ value, onValueChange }: FilterTextFieldProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  useKey(
    "/",
    (e: KeyboardEvent) => {
      const active = document.activeElement as HTMLElement;
      const isEditable =
        active?.tagName === "INPUT" || active?.tagName === "TEXTAREA" || active?.isContentEditable;

      if (!isEditable) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    },
    { event: "keydown" },
    []
  );

  useKey(
    "Escape",
    (e: KeyboardEvent) => {
      if (document.activeElement === inputRef.current) {
        e.preventDefault();
        onValueChange("");
        inputRef.current?.blur();
      }
    },
    { event: "keydown" },
    [onValueChange]
  );

  const handleClear = () => onValueChange("");

  const handleOnChange = (ev: React.ChangeEvent<HTMLInputElement>) => {
    onValueChange(ev.target.value);
  };

  return (
    <InputGroup
      px={1}
      startElement={<LuSearch size={12} style={{ marginInlineStart: "-4px" }} />}
      endElement={
        <CloseButton
          variant="plain"
          size="2xs"
          me={-1.5}
          disabled={value.trim().length === 0}
          onClick={handleClear}
        />
      }
    >
      <Input
        ref={inputRef}
        size="2xs"
        placeholder="filter..."
        value={value}
        onChange={handleOnChange}
        height="var(--chakra-sizes-6)"
        focusRing="none"
      />
    </InputGroup>
  );
}
