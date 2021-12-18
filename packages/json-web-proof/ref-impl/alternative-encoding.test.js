const { compactJwpProof, expandJwpProof } = require("./jwp");
// const base64url = require("base64url");
const expandedDerivedJwp = {
  protected: { kid: "did:example:123#key-0", alg: "MDP+EdDSA", zip: "DEF" },
  payloads: ["Yg"],
  proof:
    "eyJyb290IjoiYzllYjU1YWU4OTk0M2Q0MDRmY2U2MzI3MTM4MTAxYzgwYjIyYzcxYmIzYTY2NmFkZTBiYWY5YTRiZmIzN2JjNiIsIm5vbmNlIjoidXJuOnV1aWQ6ZTJjYWRlMDQtMjg5Ny00YTUwLTk4NDItY2QyZGQ5ZGVhZTEwIiwicHJvb2ZzIjoiZUp4RnpMc09nakFVQU5CLzZhb0pscllYNm9aUjFDZytZMkkwRHREYkdud1ZMU2pFK08rNnVaM3A3TjhFYzZjdTFtbWMyWnZTcEV1a0ZpcWpQZ011NFNjWmNDcU5DVU9sZzVScFJnVmtraG5BanRJK3BnWWs4c3lFRW8yZlVrNHBrdmIvWER5c05iOHppcXRxWUFhT0ZjZFJXWTFhSlhoRlBvNjkvaTZQZW5YaTFJWjUzTkVwaXJNWDZYd0lEWnllWWlYV0lVTEJoc244Y3FkdXN0dld5eXA3TllsTW5XWHEyb25KNS9BRk45Zzl3Zz09Iiwic2lnbmF0dXJlIjoiQlVVWHZ5VE9LS0hiSHBYUTMydlc5bFJzRVB2WEZsVkF5a3l2YTFIV0pLVUdMTExyV3NwMDN4aVdNWVdOclhweUJRYUhyZHdkWk5CcEp6a0dXSlowQ1EifQ",
};

it("encode as TLV", () => {
  //   const decodedProof = JSON.parse(base64url.decode(expandedDerivedJwp.proof));
  expect(expandedDerivedJwp.proof.length).toBe(646);
  const jwp2 = compactJwpProof(expandedDerivedJwp);
  expect(jwp2.proof.length).toBe(436);
  const jwp3 = expandJwpProof(jwp2);
  expect(jwp3).toEqual(expandedDerivedJwp);
});
