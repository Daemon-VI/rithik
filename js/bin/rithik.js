#!/usr/bin/env node
// `rithik` on npm: the JavaScript port of the Python CLI (src/rithik/cli.py).
import { main } from "../lib/cli.js";

process.exitCode = await main(process.argv.slice(2));
