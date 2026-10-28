import assert from "node:assert/strict";
import { z } from "zod";
import {
  resolvedConfigurationVariableSchema,
  validateUserConfigZodType,
} from "@nomicfoundation/hardhat-zod-utils";

describe("Hardhat Zod 4 compatibility", function () {
  it("reports invalid configuration through the normal validation interface", function () {
    const errors = validateUserConfigZodType({ count: "invalid" }, z.object({ count: z.number() }));
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].path, ["count"]);
    assert.equal(typeof errors[0].message, "string");
  });

  it("accepts callable configuration fields and rejects non-callable values", function () {
    const config = {
      _type: "ResolvedConfigurationVariable",
      get: () => "", getUrl: () => "", getBigInt: () => 0n, getHexString: () => "0x",
    };
    assert.equal(resolvedConfigurationVariableSchema.safeParse(config).success, true);
    assert.equal(resolvedConfigurationVariableSchema.safeParse({ ...config, get: 123 }).success, false);
  });

  it("rejects oversized constrained arrays before validating their elements", function () {
    let visited = 0;
    const schema = z.array(z.any().transform((value) => { visited += 1; return value; })).max(1);
    const result = schema.safeParse(Array(10000).fill("input"));
    assert.equal(result.success, false);
    assert.equal(result.error.issues.length, 1);
    assert.equal(result.error.issues[0].code, "too_big");
    assert.equal(visited, 0);
  });
});
