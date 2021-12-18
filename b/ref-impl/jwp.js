const base64url = require("base64url");
const { generateProof, deriveProof, verifyProof } = require("./merkle");
const { sign, verify } = require("./jws");

const tags = {
  root: "00",
  nonce: "01",
  signature: "02",
  proofs: "03",
};

const tagsInverse = {
  "00": "root",
  "01": "nonce",
  "02": "signature",
  "03": "proofs",
};

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

const compactJwpProof = (jwp) => {
  const decodedProof = JSON.parse(base64url.decode(jwp.proof));
  const root = Buffer.from(decodedProof.root, "hex");
  const nonce = Buffer.from(decodedProof.nonce);
  const signature = Buffer.from(decodedProof.signature, "base64");
  const proofs = Buffer.from(decodedProof.proofs, "base64");
  const buff = Buffer.concat([
    Buffer.concat([
      Buffer.from(tags.root, "hex"),
      Buffer.from(root.length.toString(16), "hex"),
      root,
    ]),
    Buffer.concat([
      Buffer.from(tags.nonce, "hex"),
      Buffer.from(nonce.length.toString(16), "hex"),
      nonce,
    ]),
    Buffer.concat([
      Buffer.from(tags.signature, "hex"),
      Buffer.from(signature.length.toString(16), "hex"),
      signature,
    ]),
    Buffer.concat([
      Buffer.from(tags.proofs, "hex"),
      Buffer.from(proofs.length.toString(16), "hex"),
      proofs,
    ]),
  ]);
  return {
    ...jwp,
    proof: base64url.encode(buff),
  };
};

const expandJwpProof = (jwp) => {
  let buff = Buffer.from(jwp.proof, "base64");

  const comps = [];

  while (buff.length) {
    const tag = buff.slice(0, 1);
    const length = parseInt(buff.slice(1, 2).toString("hex"), 16); /// this seems wrong
    const value = buff.slice(2, length + 2);
    buff = buff.slice(length + 2);
    // console.log(buff);
    comps.push({ tag, length, value });
    // buff = { length: 0 };
  }
  const compObjs = comps.map((c) => {
    const t = tagsInverse[c.tag.toString("hex")];
    let v;

    if (t === "root") {
      v = c.value.toString("hex");
    } else if (t === "nonce") {
      v = c.value.toString();
    } else if (t === "proofs") {
      v = c.value.toString("base64");
    } else {
      v = base64url.encode(c.value);
    }

    return { [t]: v };
  });

  const obj = compObjs.reduce((element, aggregate = {}) => {
    return { ...aggregate, ...element };
  });

  const ordered = {
    root: obj.root,
    nonce: obj.nonce,
    proofs: obj.proofs,
    signature: obj.signature,
  };
  return {
    ...jwp,
    proof: base64url.encode(JSON.stringify(ordered)),
  };
};

module.exports = {
  generate,
  derive,
  verify: verifyJwp,
  compactJwpProof,
  expandJwpProof,
};
