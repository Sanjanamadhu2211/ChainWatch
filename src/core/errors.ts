/** Errors that map to a CLI exit code. 2 = bad input or config, 3 = the check itself failed. */
export class ChainwatchError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly exitCode: 2 | 3 = 2,
  ) {
    super(message);
    this.name = "ChainwatchError";
  }
}

export class LockfileError extends ChainwatchError {
  constructor(code: string, message: string) {
    super(code, message, 2);
  }
}

export class ConfigError extends ChainwatchError {
  constructor(message: string) {
    super("INVALID_CONFIG", message, 2);
  }
}
