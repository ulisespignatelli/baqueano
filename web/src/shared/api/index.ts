import { demoSource } from "./demo";
import { httpSource } from "./http";
import type { DataSource } from "./types";

export const api: DataSource = import.meta.env.VITE_DATA_SOURCE === "demo" ? demoSource : httpSource;
export * from "./types";
