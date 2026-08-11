#!/usr/bin/env node
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";

const root = process.cwd();
const schemaPath = join(root, "catalog/schema.json");
const entriesDir = join(root, "catalog/entries");
const indexPath = join(root, "catalog/index.json");
const galleryPath = join(root, "catalog/gallery.json");
const metaPath = join(root, "catalog/meta.json");

const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as object;
const ajv = new Ajv2020({ allErrors: true, strict: false });
const validate = ajv.compile(schema);

let entries: unknown[] = [];
let source = "none";

if (existsSync(entriesDir)) {
  const files = readdirSync(entriesDir).filter((f) => f.endsWith(".json"));
  if (files.length) {
    source = "sharded";
    for (const f of files) {
      try {
        entries.push(
          JSON.parse(readFileSync(join(entriesDir, f), "utf8")) as unknown,
        );
      } catch (err) {
        console.error(`bad file ${f}:`, err);
        process.exit(1);
      }
    }
  }
}

if (!entries.length && existsSync(galleryPath)) {
  const raw = JSON.parse(readFileSync(galleryPath, "utf8")) as unknown;
  if (Array.isArray(raw)) {
    source = "monolith";
    entries = raw;
  } else if (
    raw &&
    typeof raw === "object" &&
    (raw as { deprecated?: boolean }).deprecated
  ) {
    source = "pointer";
    entries = [];
  } else {
    console.error("gallery.json must be an array or sharded pointer");
    process.exit(1);
  }
}

// Empty catalog is OK in CI/git: entries/index are gitignored and filled by sync/factory.
if (source === "none" && !existsSync(indexPath)) {
  if (!existsSync(schemaPath) || !existsSync(metaPath)) {
    console.error("missing catalog/schema.json or catalog/meta.json");
    process.exit(1);
  }
  console.log(
    "ok: 0 entries (empty sharded catalog — run catalog sync / factory to populate)",
  );
  process.exit(0);
}

let failed = 0;
for (let i = 0; i < entries.length; i++) {
  if (!validate(entries[i])) {
    failed++;
    if (failed <= 10) console.error(`entry[${i}]`, validate.errors);
  }
}

if (existsSync(indexPath)) {
  const index = JSON.parse(readFileSync(indexPath, "utf8")) as {
    storage?: string;
    entries?: unknown[];
  };
  if (index.storage !== "sharded") {
    console.warn("index.json storage should be \"sharded\"");
  }
  if (source === "sharded" && index.entries) {
    if (index.entries.length !== entries.length) {
      console.warn(
        `index count ${index.entries.length} != entry files ${entries.length}`,
      );
    }
  }
}

if (existsSync(metaPath)) {
  const meta = JSON.parse(readFileSync(metaPath, "utf8")) as {
    schemaVersion?: string;
    storage?: string;
  };
  if (!meta.schemaVersion) {
    console.warn("meta.json missing schemaVersion");
  }
}

if (failed) {
  console.error(`validation failed: ${failed}/${entries.length}`);
  process.exit(1);
}

console.log(
  `ok: ${entries.length} entries validated (${source})${existsSync(indexPath) ? " + index.json" : ""}`,
);
