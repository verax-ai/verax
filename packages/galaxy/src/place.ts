import { hashPoint, type Point3 } from "./address.ts";
import { isMeasured } from "./measured.ts";
import {
  agentAppearance,
  coreAppearance,
  planetAppearance,
  planetRingAppearance,
  starFlagColor,
  type Appearance,
  type Rgb,
} from "./draw.ts";
import { UNASSIGNED_CLOUD_ID, type GalaxyModel } from "./model.ts";

export const SCENE_RADIUS = 48;

export type PlacedPlanet = {
  id: string;
  label: string;
  at: Point3;
  look: Appearance;
  ring: Appearance | null;
};

export type PlacedStar = {
  id: string;
  planetId: string | null;
  at: Point3;
  flag: Rgb | null;
};

export type PlacedAgent = {
  id: string;
  label: string;
  at: Point3;
  look: Appearance;
  witness: "self" | "same-org" | undefined;
  /** Where the record's measured fields came from, or why they did not. */
  source: string;
};

export type PlacedEdge = {
  fromId: string;
  toId: string;
  kind: string;
  from: Point3;
  to: Point3;
};

export type PlacedScene = {
  core: Appearance;
  planets: PlacedPlanet[];
  stars: PlacedStar[];
  agents: PlacedAgent[];
  edges: PlacedEdge[];
};

function planetAnchor(id: string): Point3 {
  return hashPoint(`planet:${id}`, SCENE_RADIUS * 1.15);
}

export function placeScene(model: GalaxyModel): PlacedScene {
  const planets = model.planets.map((p) => ({
    id: p.id,
    label: p.label,
    at: planetAnchor(p.id),
    look: planetAppearance(p),
    ring: p.ring ? planetRingAppearance(p.ring) : null,
  }));
  const planetAt = new Map(planets.map((p) => [p.id, p.at]));

  const stars = model.stars.map((s) => {
    const home = s.planetId ? planetAt.get(s.planetId) : undefined;
    const off = hashPoint(s.id, home ? 3.5 : SCENE_RADIUS * 0.32);
    const at = home
      ? { x: home.x + off.x, y: home.y + off.y * 0.55, z: home.z + off.z }
      : off;
    return { id: s.id, planetId: s.planetId, at, flag: starFlagColor(s.flag) };
  });

  const agents = model.agents.map((a) => {
    const home = a.planetId ? planetAt.get(a.planetId) : undefined;
    const off = hashPoint(`agent:${a.id}`, SCENE_RADIUS * 0.78);
    const at = home
      ? { x: home.x + off.x * 0.12, y: home.y + 1.2, z: home.z + off.z * 0.12 }
      : off;
    return {
      id: a.id,
      label: a.label,
      at,
      look: agentAppearance(a),
      witness: a.witness,
      source: isMeasured(a.lastActMs) ? a.lastActMs.source : a.lastActMs.why,
    };
  });

  const byId = new Map<string, Point3>();
  byId.set("core", { x: 0, y: 0, z: 0 });
  byId.set(UNASSIGNED_CLOUD_ID, { x: 0, y: 0, z: 0 });
  for (const p of planets) byId.set(p.id, p.at);
  for (const s of stars) byId.set(s.id, s.at);
  for (const a of agents) byId.set(a.id, a.at);

  const edges: PlacedEdge[] = [];
  for (const e of model.edges) {
    const from = byId.get(e.fromId);
    const to = byId.get(e.toId);
    if (!from || !to) continue;
    edges.push({ ...e, from, to });
  }

  return {
    core: coreAppearance(model.core),
    planets,
    stars,
    agents,
    edges,
  };
}
