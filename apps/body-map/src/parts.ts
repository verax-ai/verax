export const LABEL_IDS = ["head", "face", "core", "left-hand", "right-hand", "torso", "ground"] as const;

export type LabelId = (typeof LABEL_IDS)[number];

export const COPY_GROUP: Record<LabelId, "head" | "face" | "core" | "hands" | "torso" | "ground"> = {
  head: "head",
  face: "face",
  core: "core",
  "left-hand": "hands",
  "right-hand": "hands",
  torso: "torso",
  ground: "ground",
};

export const LEFT_LABELS: LabelId[] = ["head", "face", "core", "left-hand", "torso"];
export const RIGHT_LABELS: LabelId[] = ["right-hand", "ground"];

export const LINK_HREF: Record<string, string | null> = {
  "tugra-ai.com": "https://tugra-ai.com/",
  "talamus.dev": "https://talamus.dev/",
  "verax-ai.com": "https://verax-ai.com/",
  "cedulon.com": "https://cedulon.com/",
  "conarium.dev": "https://conarium.dev/",
  "—": null,
};
