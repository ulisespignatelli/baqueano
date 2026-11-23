import { useOutletContext } from "react-router-dom";
import type { OrgDetail, Snapshot } from "@/shared/api/types";

export interface OrgContext {
  org: OrgDetail;
  snapshot?: Snapshot;
  snapshotId?: string;
}

export const useOrgContext = () => useOutletContext<OrgContext>();
