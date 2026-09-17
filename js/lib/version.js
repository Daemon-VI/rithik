// The version lives in package.json only, so an npm version bump needs no second edit here.
// (The Python package keeps its own copy in src/rithik/__init__.py.)
import { readFileSync } from "node:fs";

const packageJson = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));

export const VERSION = packageJson.version;
