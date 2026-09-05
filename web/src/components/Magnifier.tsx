import { useState } from "react";
import { Box, Image } from "@chakra-ui/react";

interface MagnifierPosition {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface MagnifierProps {
  src?: string;
}

export function Magnifier({ src }: MagnifierProps) {
  const [position, setPosition] = useState<MagnifierPosition | null>(null);

  return (
    <Box
      position="relative"
      display="inline-block"
      maxW="100%"
      cursor="crosshair"
      onMouseMove={(event) => {
        const bounds = event.currentTarget.getBoundingClientRect();
        setPosition({
          x: event.clientX - bounds.left,
          y: event.clientY - bounds.top,
          width: bounds.width,
          height: bounds.height,
        });
      }}
      onMouseLeave={() => setPosition(null)}
    >
      <Image
        border={0.5}
        borderRadius={5}
        borderColor="fg.subtle"
        borderStyle="solid"
        src={src}
        alt="screenshot"
        objectFit="cover"
        display="block"
        maxW="100%"
      />
      {position && (
        <Box
          position="absolute"
          top={`${position.y}px`}
          left={`${position.x}px`}
          transform="translate(-50%, -50%)"
          boxSize="140px"
          borderRadius="full"
          borderWidth="3px"
          borderColor="white"
          boxShadow="lg"
          pointerEvents="none"
          backgroundImage={`url(${src})`}
          backgroundRepeat="no-repeat"
          backgroundSize={`${position.width * 2.5}px ${position.height * 2.5}px`}
          backgroundPosition={`${70 - position.x * 2.5}px ${70 - position.y * 2.5}px`}
        />
      )}
    </Box>
  );
}
