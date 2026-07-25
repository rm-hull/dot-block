# Project Context: DoT Block - Web UI

## Overview
The `web/` directory contains the React-based frontend for the DoT Block DNS-over-TLS server.

## Stack
- **Framework:** React 19 (Vite)
- **UI:** Chakra UI v3
- **Routing:** TanStack Router
- **Data:** TanStack React Query

## Development Guidelines
- **UI:** Use Chakra UI v3 components.
- **Routing:** Use TanStack Router; run `pnpm run build` to auto-generate `routeTree.gen.ts`.
- **Package Manager:** Use `pnpm` exclusively for managing dependencies and running scripts.
- **Testing:** Prioritize `test-first` development with `vitest` (if configured) or standard React testing patterns.
- **Architecture:** Keep API services under `src/service/` and UI components under `src/components/`.
- **Verification:** Always run `pnpm run build` after making changes to ensure no build regressions.
