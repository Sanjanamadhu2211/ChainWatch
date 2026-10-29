import { buildCli } from "./helpers";

// Builds dist/index.js once before any test file runs. Building per file let parallel
// test files overwrite the bundle while another file was executing it.
export default function setup(): void {
  buildCli();
}
