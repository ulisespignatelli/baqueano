import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./Layout";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { NewOrgPage } from "@/features/setup/NewOrgPage";
import { OrgLayout } from "@/features/orgs/OrgLayout";
import { FindingsPage } from "@/features/findings/FindingsPage";
import { AssetsPage } from "@/features/assets/AssetsPage";
import { ServicesPage } from "@/features/services/ServicesPage";
import { ChangesPage } from "@/features/changes/ChangesPage";
import { SettingsPage } from "@/features/setup/SettingsPage";
import { AboutPage } from "@/features/overview/AboutPage";
import { IntelPage } from "@/features/intel/IntelPage";
import { CVEPage } from "@/features/intel/CVEPage";
import { Empty } from "@/shared/ui";
import { ApiError } from "@/shared/api/types";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 15_000, refetchOnWindowFocus: false, retry: (n, err) => !(err instanceof ApiError && err.status < 500) && n < 2 },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<OverviewPage />} />
            <Route path="orgs/new" element={<NewOrgPage />} />
            <Route path="orgs/:id" element={<OrgLayout />}>
              <Route index element={<Navigate to="findings" replace />} />
              <Route path="findings" element={<FindingsPage />} />
              <Route path="assets" element={<AssetsPage />} />
              <Route path="services" element={<ServicesPage />} />
              <Route path="changes" element={<ChangesPage />} />
              <Route path="settings" element={<SettingsPage />} />
            </Route>
            <Route path="intel" element={<IntelPage />} />
            <Route path="intel/cve/:id" element={<CVEPage />} />
            <Route path="about" element={<AboutPage />} />
            <Route path="*" element={<Empty title="Página inexistente" />} />
          </Route>
        </Routes>
      </HashRouter>
    </QueryClientProvider>
  );
}
