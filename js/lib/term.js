// Terminal plumbing shared by the card and the scam report: colour, and how text reaches the
// process streams. The port of src/rithik/_term.py.

export const RESET = "\x1b[0m";
export const BOLD = "1";
export const DIM = "2";
export const RED = "1;31";
export const GREEN = "1;32";
export const YELLOW = "1;33";
export const CYAN = "36";
export const BOLD_CYAN = "1;36";

export function paint(text, code, color) {
  if (!color || !text) return text;
  return `\x1b[${code}m${text}${RESET}`;
}

/**
 * Whether to colour a stream, by the same rules as the Python version: --no-color or a
 * non-empty NO_COLOR (no-color.org) turn it off, a stream that is not a terminal never gets it,
 * and outside Windows TERM=dumb turns it off.
 *
 * Python has to call SetConsoleMode on Windows to turn on escape-code processing, and keeps
 * colour off when that fails. Node needs no such step: libuv's Windows console writer turns on
 * virtual terminal processing itself and, on consoles without it, interprets the escape codes
 * and makes the equivalent console API calls. So a Windows terminal always gets colour here.
 */
export function colorEnabled({ disabled, env, isTTY, platform }) {
  if (disabled || (env && env.NO_COLOR)) return false;
  let tty;
  try {
    tty = Boolean(isTTY());
  } catch {
    return false;
  }
  if (!tty) return false;
  if (platform === "win32") return true;
  return (env && env.TERM) !== "dumb";
}

/**
 * A writer for a real process stream. On Windows, Python's sys.stdout and sys.stderr are text
 * streams that turn "\n" into "\r\n", so `rithik > out.txt` holds CRLF line endings there;
 * writing the same bytes keeps redirected output identical. Node's own writes stay UTF-8, where
 * Python would encode a pipe with the ANSI code page and put "?" for what it cannot hold.
 */
export function processWriter(stream, platform) {
  const crlf = platform === "win32";
  return {
    write(text) {
      stream.write(crlf ? text.replace(/\n/g, "\r\n") : text);
    },
  };
}

let pipeGuardInstalled = false;

/**
 * `rithik | head` closing the pipe early is the reader's choice, not an error: Python catches
 * BrokenPipeError and exits 0. In Node the failure arrives later as an 'error' event, which
 * would otherwise crash the process with a stack trace.
 */
export function ignoreBrokenPipes(proc) {
  if (pipeGuardInstalled) return;
  pipeGuardInstalled = true;
  for (const stream of [proc.stdout, proc.stderr]) {
    stream.on("error", (err) => {
      if (err && err.code === "EPIPE") {
        proc.exitCode = 0;
        return;
      }
      throw err;
    });
  }
}
