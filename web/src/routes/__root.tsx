import React, { useRef } from "react";
import { CatchBoundary, Outlet, createRootRoute } from "@tanstack/react-router";
import { ErrorFallback } from "@rm-hull/chakra-error-fallback";
import { Navbar, NavbarToolbarContext } from "@/components/Navbar";
import { Provider } from "@/components/ui/provider";
import { Toaster } from "@/components/ui/toaster";
import { Loading } from "@/components/Loading";
import { useAuth } from "@/hooks/useAuth";

// eslint-disable-next-line react-refresh/only-export-components
const TanStackRouterDevtools = import.meta.env.PROD
  ? () => null
  : React.lazy(() =>
    import("@tanstack/react-router-devtools").then((res) => ({
      default: res.TanStackRouterDevtools,
    }))
  );

export const Route = createRootRoute({
  component: () => {
    const toolbarHostRef = useRef<HTMLDivElement | null>(null);

    const { data, isLoading } = useAuth();

    if (isLoading) {
      return (
        <Provider>
          <Loading />
        </Provider>
      );
    }

    if (!data) {
      throw new Error("User unknown or not authorized");
    }

    return (
      <Provider>
        <NavbarToolbarContext.Provider value={toolbarHostRef}>
          <CatchBoundary getResetKey={() => "reset"} errorComponent={ErrorFallback}>
            <Toaster />
            <Navbar user={data} />
            <Outlet />
          </CatchBoundary>
          <React.Suspense>
            <TanStackRouterDevtools />
          </React.Suspense>
        </NavbarToolbarContext.Provider>
      </Provider>
    );
  },
});
