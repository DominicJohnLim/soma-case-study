import { test } from "node:test";
import assert from "node:assert/strict";
import { ContentStore, IntegrityError } from "../src/cas.ts";
import { sha256 } from "../src/canonical.ts";

test("round trip: bytes come back exactly, addressed by their hash", () => {
  const store = new ContentStore();
  const address = store.putText("investment memo v1");
  assert.equal(address, sha256(new TextEncoder().encode("investment memo v1")));
  assert.equal(store.getText(address), "investment memo v1");
});

test("put is idempotent: same bytes, same address", () => {
  const store = new ContentStore();
  assert.equal(store.putText("dup"), store.putText("dup"));
});

test("tampered backing bytes are detected on read, never returned", () => {
  const store = new ContentStore();
  const address = store.putText("original artifact");
  // Simulate storage-layer tampering behind the API's back.
  store.unsafeRawMap().set(address, new TextEncoder().encode("silently altered"));
  assert.throws(() => store.get(address), IntegrityError);
});

test("missing artifact throws instead of returning undefined", () => {
  const store = new ContentStore();
  assert.throws(() => store.get("sha256:" + "0".repeat(64)), IntegrityError);
});
