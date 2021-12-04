const { generateProof, deriveProof, verifyProof } = require("./merkle");

const messages = ["a", "b", "c"];

const proof = {
  rootNonce: "urn:uuid:e2cade04-2897-4a50-9842-cd2dd9deae10",
  root: "c9eb55ae89943d404fce6327138101c80b22c71bb3a666ade0baf9a4bfb37bc6",
  proofs:
    "eJyVzNsSQkAAANB/8aqZVcuWR+RSa5lqiG160KIhubRW6uv7hs4HnItkRGUDrfZMSwpH0nadopp57CIWeEHyGgo81TjV2YaMWBhF5aIPqiftqJ02OeqhS8JmWHJMk/kgbu8P0TPeQfZUHGkhGY4Qdmlz2N+9UXjyiEBf7RywpZVhzoSzCAKVL/1ce4B/a6vOuFxQwN9izTr9RTPP9aMY0yBY7XmUhm1c2dbcDuIrXX8d+kvi",
};

const derivedProof =
  "eJxFzLsOgjAUANB/6aoJlrYX6oZR1Cg+Y2I0DtDbGnwVLSjE+O+6uZ3p7N8Ec6cu1mmc2ZvSpEukFiqjPgMu4ScZcCqNCUOlg5RpRgVkkhnAjtI+pgYk8syEEo2fUk4pkvb/XDysNb8ziqtqYAaOFcdRWY1aJXhFPo69/i6PenXi1IZ53NEpirMX6XwIDZyeYiXWIULBhsn8cqdustvWyyp7NYlMnWXq2onJ5/AFN9g9wg==";

describe("generateProof", () => {
  it("should produce a set membership proof", () => {
    const p1 = generateProof(messages, proof.rootNonce);
    expect(p1).toEqual(proof);
  });
});

describe("deriveProof", () => {
  it("should produce a subset membership proof from a set membership proof", () => {
    const d1 = deriveProof([1], proof.proofs, messages, proof.rootNonce);
    expect(d1).toEqual(derivedProof);
  });
});

describe("verifyProof", () => {
  it("should succeed when message is in subset", () => {
    const v1 = verifyProof(["b"], derivedProof, proof.root);
    expect(v1).toEqual(true);
  });

  it("should fail when message is not in subset", () => {
    const v1 = verifyProof(["a"], derivedProof, proof.root);
    expect(v1).toEqual(false);
  });
});
