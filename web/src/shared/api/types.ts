// Tipos derivados del contrato (api/openapi.yaml → schema.gen.ts).
import type { components } from "./schema.gen";

type S = components["schemas"];
export type Health = S["Health"];
export type Overview = S["Overview"];
export type OrgSummary = S["OrgSummary"];
export type OrgDetail = S["OrgDetail"];
export type Organization = S["Organization"];
export type Domain = S["Domain"];
export type SnapshotMeta = S["SnapshotMeta"];
export type Snapshot = S["Snapshot"];
export type Asset = S["Asset"];
export type Service = S["Service"];
export type Finding = S["Finding"];
export type Vuln = S["Vuln"];
export type Changes = S["Changes"];
export type Job = S["Job"];
export type Severity = S["Severity"];
export type CreateOrgRequest = S["CreateOrgRequest"];
export type AuditEvent = S["AuditEvent"];
export type IntelStatus = S["IntelStatus"];
export type CVEInfo = S["CVEInfo"];
export type Confidence = S["Confidence"];
export type SSVC = S["SSVC"];
export type Range = S["Range"];

export interface DataSource {
  readonly mode: "api" | "demo";
  health(): Promise<Health>;
  overview(): Promise<Overview>;
  org(id: string): Promise<OrgDetail>;
  snapshot(id: string): Promise<Snapshot>;
  changes(id: string): Promise<Changes>;
  createOrg(req: CreateOrgRequest): Promise<Organization>;
  addDomain(id: string, domain: string): Promise<Organization>;
  verify(id: string): Promise<Organization>;
  addNetwork(id: string, network: string): Promise<Organization>;
  attest(id: string, by: string): Promise<Organization>;
  deleteOrg(id: string): Promise<void>;
  startScan(id: string): Promise<Job>;
  job(id: string): Promise<Job>;
  startReassess(id: string): Promise<Job>;
  intel(): Promise<IntelStatus>;
  updateIntel(): Promise<IntelStatus>;
  cve(id: string): Promise<CVEInfo>;
  exportUrl(id: string, format: "json" | "csv"): string | null;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
