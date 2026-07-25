import { Provider } from "@/components/ui/provider"
import { Navbar } from "@/components/Navbar"
import { CatchBoundary, Outlet, createRootRoute } from "@tanstack/react-router"
import React from "react"
import { ErrorFallback } from "@rm-hull/chakra-error-fallback";
import { Toaster } from "@/components/ui/toaster";

// eslint-disable-next-line react-refresh/only-export-components
const TanStackRouterDevtools =
  import.meta.env.PROD
    ? () => null
    : React.lazy(() =>
      import("@tanstack/react-router-devtools").then((res) => ({
        default: res.TanStackRouterDevtools,
      })),
    )

export const Route = createRootRoute({
  component: () => (
    <Provider>
      <CatchBoundary getResetKey={() => "reset"} errorComponent={ErrorFallback}>
        <Toaster />
        <Navbar />
        <Outlet />
      </CatchBoundary>
      <React.Suspense>
        <TanStackRouterDevtools />
      </React.Suspense>
    </Provider>
  ),
})
