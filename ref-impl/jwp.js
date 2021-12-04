const base64url = require("base64url");
const { generateProof, deriveProof, verifyProof } = require("./merkle");
const { sign, verify } = require("./jws");

const compactJwp = (jwp) => {
  const header = base64url.encode(JSON.stringify(jwp.protected));
  return header + "." + jwp.payloads.join("~") + "." + jwp.proof;
};

// TODO:
// const expandJwp = (jwp) => {
// ...
// };

const generate = async (
  payloads,
  privateKeyJwk,
  options = { compact: true }
) => {
  const { nonce } = options;
  const intermediateProof = generateProof(payloads, nonce);
  const signature = await sign({}, intermediateProof.root, privateKeyJwk);
  const [encodedHeader, _, encodedSignature] = signature.split(".");
  const decodedHeader = JSON.parse(base64url.decode(encodedHeader));
  const { alg } = decodedHeader;
  const { kid } = privateKeyJwk;
  const header = {
    kid: kid,
    alg: `MDP+${alg}`,
    zip: "DEF",
  };
  const finalProof = {
    root: intermediateProof.root, // avoid double encoding root
    nonce: intermediateProof.rootNonce,
    proofs: intermediateProof.proofs,
    signature: encodedSignature, // avoid double double encoding header
  };
  const encodedProof = base64url.encode(JSON.stringify(finalProof));
  const encodedPayloads = payloads.map((p) => {
    const text = typeof p === "string" ? p : JSON.stringify(p);
    return base64url.encode(text);
  });
  const expandedJwp = {
    protected: header,
    payloads: encodedPayloads,
    proof: encodedProof,
  };
  if (!options.compact) {
    return expandedJwp;
  }
  return compactJwp(expandedJwp);
};

const derive = async (payloads, expandedJwp) => {
  const decodedPayloads = expandedJwp.payloads.map((p) => {
    return base64url.decode(p);
  });
  const disclosedIndexes = payloads.map((p) => {
    const i = decodedPayloads.indexOf(p);
    if (i < 0) {
      throw new Error(`No proof for payload "${p}"", at index ${i}`);
    }
    return i;
  });
  const decodedProof = JSON.parse(base64url.decode(expandedJwp.proof));

  const derivedProof = deriveProof(
    disclosedIndexes,
    decodedProof.proofs,
    decodedPayloads,
    decodedProof.nonce
  );

  const finalProof = {
    root: decodedProof.root, // avoid double encoding root
    nonce: decodedProof.nonce,
    proofs: derivedProof,
    signature: decodedProof.signature, // avoid double double encoding header
  };
  const encodedDerivedProof = base64url.encode(JSON.stringify(finalProof));

  const encodedPayloads = payloads.map((p) => {
    const text = typeof p === "string" ? p : JSON.stringify(p);
    return base64url.encode(text);
  });

  const derivedExpandedJwp = {
    protected: expandedJwp.protected, // always stays the same
    payloads: encodedPayloads,
    proof: encodedDerivedProof,
  };

  return derivedExpandedJwp;
};

const verifyJwp = async (expandedJwp, publicKeyJwk) => {
  try {
    const decodedProof = JSON.parse(base64url.decode(expandedJwp.proof));
    const alg = expandedJwp.protected.alg.split("+").pop();
    const encodedHeader = base64url.encode(JSON.stringify({ alg }));
    const encodedPayload = base64url.encode(decodedProof.root);
    const jws = `${encodedHeader}.${encodedPayload}.${decodedProof.signature}`;
    const isRootVerified = await verify(jws, publicKeyJwk);
    if (!isRootVerified) {
      return false;
    }
    const decodedPayloads = expandedJwp.payloads.map((p) => {
      return base64url.decode(p);
    });
    const isMerkleProofVerified = verifyProof(
      decodedPayloads,
      decodedProof.proofs,
      decodedProof.root
    );
    return isMerkleProofVerified;
  } catch (e) {
    return false;
  }
};

module.exports = { generate, derive, verify: verifyJwp };
