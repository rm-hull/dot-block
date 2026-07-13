import { Provider } from "@/components/ui/provider"
import { Outlet, createRootRoute } from "@tanstack/react-router"

export const Route = createRootRoute({
  component: () => <Provider><Outlet /></Provider>,
})