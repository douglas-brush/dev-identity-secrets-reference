/**
 * Unit tests for SOPS helpers.
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { execFileSync } from "child_process";

import {
  detectFormat,
  parseDotenv,
  parseSopsConfig,
  sopsConfigHasCloudKms,
  sopsConfigRulesForPath,
} from "../src/sops";

// We mock child_process for decrypt/encrypt tests since sops may not be installed
jest.mock("child_process", () => {
  const actual = jest.requireActual("child_process");
  return {
    ...actual,
    execFileSync: jest.fn(),
    execSync: jest.fn(),
  };
});

const mockedExecFileSync = execFileSync as jest.MockedFunction<typeof execFileSync>;
const { execSync: mockedExecSync } = require("child_process") as {
  execSync: jest.MockedFunction<typeof import("child_process").execSync>;
};

// ------------------------------------------------------------------
// Format Detection
// ------------------------------------------------------------------

describe("detectFormat", () => {
  test("json", () => {
    expect(detectFormat("secret.enc.json")).toBe("json");
  });

  test("yaml", () => {
    expect(detectFormat("secret.enc.yaml")).toBe("yaml");
  });

  test("yml", () => {
    expect(detectFormat("secret.enc.yml")).toBe("yaml");
  });

  test("plain yaml", () => {
    expect(detectFormat("config.yaml")).toBe("yaml");
  });

  test("unknown defaults to json", () => {
    expect(detectFormat("file.txt")).toBe("json");
  });
});

// ------------------------------------------------------------------
// Dotenv Parser
// ------------------------------------------------------------------

describe("parseDotenv", () => {
  test("parses key=value pairs", () => {
    const content = [
      "# comment",
      "DB_HOST=localhost",
      'DB_PASS="quoted value"',
      "EMPTY=",
    ].join("\n");

    const result = parseDotenv(content);
    expect(result["DB_HOST"]).toBe("localhost");
    expect(result["DB_PASS"]).toBe("quoted value");
    expect(result["EMPTY"]).toBe("");
  });

  test("skips comments and blank lines", () => {
    const content = "# this is a comment\n\nKEY=val\n";
    const result = parseDotenv(content);
    expect(Object.keys(result)).toEqual(["KEY"]);
  });
});

// ------------------------------------------------------------------
// SopsConfig Parsing
// ------------------------------------------------------------------

describe("parseSopsConfig", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sops-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("parse valid config", () => {
    const configPath = path.join(tmpDir, ".sops.yaml");
    fs.writeFileSync(
      configPath,
      [
        "creation_rules:",
        "  - path_regex: secrets/dev/.*\\.enc\\.yaml$",
        "    age: 'age1abc'",
        "    encrypted_regex: '^(password|token)$'",
        "  - path_regex: secrets/prod/.*\\.enc\\.yaml$",
        "    kms: 'arn:aws:kms:us-east-1:111:key/abc'",
        "    age: 'age1xyz'",
        "    encrypted_regex: '^(password|token)$'",
      ].join("\n")
    );

    const config = parseSopsConfig(configPath);
    expect(config.creation_rules.length).toBe(2);
    expect(config.creation_rules[0]!.age).toBe("age1abc");
    expect(config.creation_rules[1]!.kms).toContain("arn:aws");
  });

  test("parse missing file throws", () => {
    expect(() => parseSopsConfig("/nonexistent/.sops.yaml")).toThrow();
  });

  test("has_cloud_kms", () => {
    const configPath = path.join(tmpDir, ".sops.yaml");
    fs.writeFileSync(
      configPath,
      [
        "creation_rules:",
        "  - path_regex: dev/.*",
        "    age: 'age1abc'",
        "  - path_regex: prod/.*",
        "    kms: 'arn:aws:kms:us-east-1:111:key/abc'",
      ].join("\n")
    );

    const config = parseSopsConfig(configPath);
    expect(sopsConfigHasCloudKms(config)).toBe(true);
    expect(sopsConfigHasCloudKms(config, 0)).toBe(false);
    expect(sopsConfigHasCloudKms(config, 1)).toBe(true);
  });

  test("rules_for_path", () => {
    const configPath = path.join(tmpDir, ".sops.yaml");
    fs.writeFileSync(
      configPath,
      [
        "creation_rules:",
        "  - path_regex: secrets/dev/.*\\.enc\\.yaml$",
        "    age: 'age1dev'",
        "  - path_regex: secrets/prod/.*\\.enc\\.yaml$",
        "    age: 'age1prod'",
      ].join("\n")
    );

    const config = parseSopsConfig(configPath);
    const matches = sopsConfigRulesForPath(config, "secrets/dev/app.enc.yaml");
    expect(matches.length).toBe(1);
    expect(matches[0]!.age).toBe("age1dev");

    const noMatch = sopsConfigRulesForPath(config, "other/file.yaml");
    expect(noMatch.length).toBe(0);
  });
});

// ------------------------------------------------------------------
// decryptFile (mocked)
// ------------------------------------------------------------------

describe("decryptFile", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sops-decrypt-"));
    jest.resetAllMocks();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("file not found throws Error", () => {
    // Importing directly to test with mocked child_process
    const { decryptFile } = require("../src/sops");
    expect(() => decryptFile("/nonexistent/file.enc.yaml")).toThrow("File not found");
  });

  test("decrypt json success", () => {
    // Setup: mock sops binary found
    mockedExecSync.mockReturnValue("/usr/local/bin/sops" as any);
    mockedExecFileSync.mockReturnValue('{"password": "plaintext-value"}' as any);

    const encFile = path.join(tmpDir, "secret.enc.json");
    fs.writeFileSync(encFile, '{"sops": {}, "password": "ENC[...]"}');

    const { decryptFile } = require("../src/sops");
    const result = decryptFile(encFile);
    expect(result).toEqual({ password: "plaintext-value" });
  });

  test("decrypt yaml success", () => {
    mockedExecSync.mockReturnValue("/usr/local/bin/sops" as any);
    mockedExecFileSync.mockReturnValue("password: my-secret\n" as any);

    const encFile = path.join(tmpDir, "secret.enc.yaml");
    fs.writeFileSync(encFile, "password: ENC[...]");

    const { decryptFile } = require("../src/sops");
    const result = decryptFile(encFile);
    expect(result).toEqual({ password: "my-secret" });
  });

  test("decrypt failure throws SopsDecryptError", () => {
    mockedExecSync.mockReturnValue("/usr/local/bin/sops" as any);
    const error = new Error("sops failed") as any;
    error.status = 1;
    error.stdout = "";
    error.stderr = "Error: could not decrypt";
    mockedExecFileSync.mockImplementation(() => {
      throw error;
    });

    const encFile = path.join(tmpDir, "bad.enc.json");
    fs.writeFileSync(encFile, "{}");

    const { decryptFile } = require("../src/sops");
    const { SopsDecryptError } = require("../src/exceptions");
    expect(() => decryptFile(encFile)).toThrow(SopsDecryptError);
  });

  test("sops not installed throws SopsNotInstalledError", () => {
    mockedExecSync.mockImplementation(() => {
      throw new Error("not found");
    });

    const encFile = path.join(tmpDir, "secret.enc.json");
    fs.writeFileSync(encFile, "{}");

    const { decryptFile } = require("../src/sops");
    const { SopsNotInstalledError } = require("../src/exceptions");
    expect(() => decryptFile(encFile)).toThrow(SopsNotInstalledError);
  });
});

// ------------------------------------------------------------------
// encryptFile (mocked)
// ------------------------------------------------------------------

describe("encryptFile", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sops-encrypt-"));
    jest.resetAllMocks();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("encrypt json success", () => {
    mockedExecSync.mockReturnValue("/usr/local/bin/sops" as any);
    mockedExecFileSync.mockReturnValue(
      '{"password": "ENC[AES256_GCM,data:abc]", "sops": {}}' as any
    );

    const outPath = path.join(tmpDir, "secret.enc.json");
    const { encryptFile } = require("../src/sops");
    const result = encryptFile(outPath, { password: "my-secret" });
    expect(result).toBe(outPath);
    expect(fs.existsSync(outPath)).toBe(true);
  });

  test("encrypt failure throws SopsEncryptError", () => {
    mockedExecSync.mockReturnValue("/usr/local/bin/sops" as any);
    const error = new Error("sops failed") as any;
    error.status = 1;
    error.stdout = "";
    error.stderr = "Error: no matching creation rule";
    mockedExecFileSync.mockImplementation(() => {
      throw error;
    });

    const outPath = path.join(tmpDir, "secret.enc.yaml");
    const { encryptFile } = require("../src/sops");
    const { SopsEncryptError } = require("../src/exceptions");
    expect(() => encryptFile(outPath, { key: "val" })).toThrow(SopsEncryptError);
  });
});
