const jose = require("jose");
const encoder = new TextEncoder();

const crvToAlg = {
  secp256k1: "ES256K",
  Ed25519: "EdDSA",
};

const sign = async (header, payload, privateKeyJwk) => {
  const alg = crvToAlg[privateKeyJwk.crv];
  const jws = await new jose.CompactSign(
    encoder.encode(
      typeof payload === "string" ? payload : JSON.stringify(payload)
    )
  )
    .setProtectedHeader({ ...header, alg })
    .sign(await jose.importJWK(privateKeyJwk, alg));
  return jws;
};

const verify = async (jws, publicKeyJwk) => {
  let verified = false;
  const alg = crvToAlg[publicKeyJwk.crv];
  try {
    const { protectedHeader } = await jose.compactVerify(
      jws,
      await jose.importJWK(publicKeyJwk, alg)
    );
    if (protectedHeader.alg !== alg) {
      throw new Error("Invalid alg.");
    }
    verified = true;
  } catch (e) {
    verified = false;
  }
  return verified;
};

module.exports = { sign, verify };
