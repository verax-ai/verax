import type { Measured } from "./measured.ts";

export type StarFlag = "deny" | "ghost" | "reauth";
export type WitnessMark = "self" | "same-org";

export type GalaxyPlanet = {
  id: string;
  label: string;
  size: Measured<number>;
  freshness: Measured<number>;
  ring?: Measured<number>;
};

export type GalaxyStar = {
  id: string;
  planetId: string | null;
  at: number;
  kind: string;
  flag?: StarFlag;
};

export type GalaxyAgent = {
  id: string;
  label: string;
  planetId: string | null;
  lastActMs: Measured<number>;
  witness?: WitnessMark;
};

export type GalaxyEdge = {
  fromId: string;
  toId: string;
  kind: string;
};

export type GalaxyModel = {
  core: { pulse: Measured<number>; label: string };
  planets: GalaxyPlanet[];
  stars: GalaxyStar[];
  agents: GalaxyAgent[];
  edges: GalaxyEdge[];
};

export const UNASSIGNED_CLOUD_ID = "unassigned";
