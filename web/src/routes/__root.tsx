import { Provider } from "@/components/ui/provider"
import { Navbar } from "@/components/Navbar"
import { Outlet, createRootRoute } from "@tanstack/react-router"
import React from "react"

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
      <Navbar />
      <Outlet />
      <React.Suspense>
        <TanStackRouterDevtools />
      </React.Suspense>
    </Provider>
  ),
})
