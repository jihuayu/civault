import { describe, expect, it, vi } from "vitest";
import {
  references,
  resolveKeys,
  serverOrigin,
  validName,
} from "../src/client";

describe("explicit key references", () => {
  it("collects only explicit references and rejects unsafe names and workspaces", () => {
    expect(
      references(
        { NPM_TOKEN: "cv://ws_default/shared/npm", OTHER: "literal" },
        "ws_default",
      ),
    ).toEqual({ NPM_TOKEN: "cv://ws_default/shared/npm" });
    for (const env of [
      { PATH: "cv://ws_default/key" },
      { GITHUB_TOKEN: "cv://ws_default/key" },
      { NPM: "cv://other/key" },
      { NPM: "cv://ws_default/key?version=1" },
      { NPM: "cv://ws_default/key", npm: "cv://ws_default/key" },
    ])
      expect(() => references(env, "ws_default")).toThrow();
    expect(() => serverOrigin("http://remote.example.com")).toThrow();
    expect(() => serverOrigin("https://user:pass@vault.example.com")).toThrow();
    for (const name of [
      "__proto__",
      "constructor",
      "PROTOTYPE",
      "A".repeat(201),
    ])
      expect(validName(name)).toBe(false);
  });
  it("retries transient errors with the same JWT and request body", async () => {
    const fetcher = vi
      .fn()
      .mockRejectedValueOnce(new Error("network"))
      .mockResolvedValueOnce(new Response("{}", { status: 503 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ values: { KEY: "multiline\nvalue" } })),
      );
    const wait = vi.fn().mockResolvedValue(undefined);
    expect(
      await resolveKeys(
        "https://vault.example.com",
        "ws_default",
        { KEY: "cv://ws_default/key" },
        "jwt",
        fetcher,
        wait,
      ),
    ).toEqual({ KEY: "multiline\nvalue" });
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(
      fetcher.mock.calls
        .map((c) => c[1].body)
        .every((v) => v === fetcher.mock.calls[0][1].body),
    ).toBe(true);
    expect(
      fetcher.mock.calls.every(
        (c) =>
          c[1].headers.Authorization === "Bearer jwt" &&
          c[1].redirect === "error",
      ),
    ).toBe(true);
  });
  it("does not retry denials or accept partial/unexpected values", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValue(new Response("{}", { status: 403 }));
    await expect(
      resolveKeys(
        "https://vault.example.com",
        "ws_default",
        { KEY: "cv://ws_default/key" },
        "jwt",
        fetcher,
      ),
    ).rejects.toThrow("403");
    expect(fetcher).toHaveBeenCalledTimes(1);
    for (const values of [
      {},
      { KEY: "secret", OTHER: "unexpected" },
      { KEY: "nul\0value" },
      { KEY: 1 },
    ])
      await expect(
        resolveKeys(
          "https://vault.example.com",
          "ws_default",
          { KEY: "cv://ws_default/key" },
          "jwt",
          vi.fn().mockResolvedValue(new Response(JSON.stringify({ values }))),
        ),
      ).rejects.toThrow("invalid");
  });
  it("retries an interrupted response body without exposing partial values", async () => {
    const interrupted = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error("connection reset"));
      },
    });
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(new Response(interrupted))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ values: { KEY: "complete" } })),
      );
    expect(
      await resolveKeys(
        "https://vault.example.com",
        "ws_default",
        { KEY: "cv://ws_default/key" },
        "jwt",
        fetcher,
        async () => {},
      ),
    ).toEqual({ KEY: "complete" });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
