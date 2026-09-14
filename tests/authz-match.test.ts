import { describe, expect, it } from "vitest";
import {
  evaluateAuthzRules,
  evaluateAuthzRulesForContexts,
  normalizeMatch,
  ruleMatches,
} from "../src/authz/match.js";
import type { AuthzRule } from "../src/authz/types.js";
import { authzMatchHasConstraint } from "../src/authz/types.js";

function rule(partial: Partial<AuthzRule> & { match: AuthzRule["match"] }): AuthzRule {
  return {
    id: partial.id ?? "r1",
    workspaceId: "ws",
    name: partial.name ?? "r",
    enabled: partial.enabled ?? true,
    priority: partial.priority ?? 0,
    match: partial.match,
    requirement: partial.requirement ?? "notify_approve",
    ttlSeconds: partial.ttlSeconds ?? 180,
    mfaReuseSeconds: partial.mfaReuseSeconds ?? 0,
    createdAt: "",
    updatedAt: "",
  };
}

describe("authz match", () => {
  it("matches exact tool, prefix, backend, placement, key", () => {
    const ctx = {
      tool: "github__delete_repo",
      keyId: "key_1",
      backendSlug: "github",
      placement: "remote" as const,
    };
    expect(
      ruleMatches(rule({ match: { tools: ["github__delete_repo"] } }), ctx),
    ).toBe(true);
    expect(ruleMatches(rule({ match: { prefixes: ["github__"] } }), ctx)).toBe(
      true,
    );
    expect(ruleMatches(rule({ match: { backends: ["github"] } }), ctx)).toBe(
      true,
    );
    expect(
      ruleMatches(rule({ match: { placements: ["remote"] } }), ctx),
    ).toBe(true);
    expect(ruleMatches(rule({ match: { keyIds: ["key_1"] } }), ctx)).toBe(
      true,
    );
    expect(
      ruleMatches(rule({ match: { prefixes: ["shell__"] } }), ctx),
    ).toBe(false);
    expect(ruleMatches(rule({ match: { keyIds: ["other"] } }), ctx)).toBe(
      false,
    );
  });

  it("ANDs constraint kinds and ORs tools with prefixes", () => {
    const ctx = {
      tool: "fs__write_file",
      keyId: "k",
      backendSlug: "fs",
      placement: "central-sandbox" as const,
    };
    expect(
      ruleMatches(
        rule({
          match: { prefixes: ["fs__"], backends: ["fs"], placements: ["remote"] },
        }),
        ctx,
      ),
    ).toBe(false);
    expect(
      ruleMatches(
        rule({
          match: {
            tools: ["nope"],
            prefixes: ["fs__"],
            backends: ["fs"],
          },
        }),
        ctx,
      ),
    ).toBe(true);
  });

  it("skips disabled rules and exempt discovery metas", () => {
    const rules = [
      rule({
        match: { prefixes: ["mf_"] },
        requirement: "mfa_and_approve",
        priority: 99,
      }),
    ];
    expect(
      evaluateAuthzRules(rules, {
        tool: "mf_status",
        keyId: "k",
        backendSlug: null,
        placement: null,
      }),
    ).toBeNull();
    expect(
      evaluateAuthzRules(rules, {
        tool: "mf_admin_key_create",
        keyId: "k",
        backendSlug: null,
        placement: null,
      })?.requirement,
    ).toBe("mfa_and_approve");
  });

  it("picks strictest requirement then priority", () => {
    const ctx = {
      tool: "github__delete_repo",
      keyId: "k",
      backendSlug: "github",
      placement: "remote" as const,
    };
    const rules = [
      rule({
        id: "notify",
        match: { prefixes: ["github__"] },
        requirement: "notify_approve",
        priority: 100,
      }),
      rule({
        id: "mfa",
        match: { tools: ["github__delete_repo"] },
        requirement: "mfa",
        priority: 0,
      }),
    ];
    expect(evaluateAuthzRules(rules, ctx)?.id).toBe("mfa");
  });

  it("picks strictest across mf_call_tool and inner name", () => {
    const rules = [
      rule({
        id: "inner",
        match: { tools: ["up__echo"] },
        requirement: "notify_approve",
        priority: 0,
      }),
      rule({
        id: "meta",
        match: { tools: ["mf_call_tool"] },
        requirement: "mfa_and_approve",
        priority: 0,
      }),
    ];
    const hit = evaluateAuthzRulesForContexts(rules, [
      {
        tool: "mf_call_tool",
        keyId: "k",
        backendSlug: null,
        placement: null,
      },
      {
        tool: "up__echo",
        keyId: "k",
        backendSlug: "up",
        placement: "remote",
      },
    ]);
    expect(hit?.id).toBe("meta");
  });

  it("normalizeMatch drops empties; empty match has no constraint", () => {
    const m = normalizeMatch({
      tools: ["  ", ""],
      prefixes: ["up__"],
      placements: ["nope", "remote"],
    });
    expect(m.tools).toBeUndefined();
    expect(m.prefixes).toEqual(["up__"]);
    expect(m.placements).toEqual(["remote"]);
    expect(authzMatchHasConstraint({})).toBe(false);
    expect(authzMatchHasConstraint(m)).toBe(true);
  });
});
