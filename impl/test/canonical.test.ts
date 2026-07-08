import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize, sha256, sha256Canonical } from "../src/canonical.ts";

test("key order does not change the canonical encoding", () => {
  const a = { b: 1, a: [{ y: "z", x: null }], c: true };
  const b = { c: true, a: [{ x: null, y: "z" }], b: 1 };
  assert.equal(canonicalize(a), canonicalize(b));
  assert.equal(sha256Canonical(a), sha256Canonical(b));
});

test("canonical form is stable and explicit", () => {
  assert.equal(canonicalize({ b: 2, a: "x" }), '{"a":"x","b":2}');
  assert.equal(canonicalize([1, "two", false, null]), '[1,"two",false,null]');
});

test("undefined-valued keys are dropped, matching JSON semantics", () => {
  assert.equal(
    canonicalize({ a: 1, gone: undefined as unknown as null }),
    '{"a":1}',
  );
});

test("non-finite and non-integer numbers are rejected", () => {
  assert.throws(() => canonicalize(Number.NaN));
  assert.throws(() => canonicalize(Infinity));
  assert.throws(() => canonicalize(0.7));
});

test("different content yields different hashes", () => {
  assert.notEqual(sha256Canonical({ a: 1 }), sha256Canonical({ a: 2 }));
  assert.notEqual(sha256("x"), sha256("y"));
});
