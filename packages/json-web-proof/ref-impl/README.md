### JSON Web Proof for Merkle Proof based Selective Disclosure

See [json-web-proofs](https://github.com/json-web-proofs/json-web-proofs).

Warning: JWP is experimental and subject to change.

These examples do not use `lyt` and are therefore not mappable to objects.

Examples:

```js
const payloads = ["a", "b", "c"];

const privateKeyJwk = {
  kid: "did:example:123#key-0",
  kty: "OKP",
  crv: "Ed25519",
  x: "DeSYrNyska2WfJ_lEzcieAWnOeK4KNXhU-J2A1TkrKI",
  d: "e9CLcJqLQK5_jEHiktAWRSZ-Hp4VTMb9lv1WwQXOSGA",
};

const expandedJwp = {
  protected: { kid: "did:example:123#key-0", alg: "MDP+EdDSA", zip: "DEF" },
  payloads: ["YQ", "Yg", "Yw"],
  proof:
    "eyJyb290IjoiYzllYjU1YWU4OTk0M2Q0MDRmY2U2MzI3MTM4MTAxYzgwYjIyYzcxYmIzYTY2NmFkZTBiYWY5YTRiZmIzN2JjNiIsIm5vbmNlIjoidXJuOnV1aWQ6ZTJjYWRlMDQtMjg5Ny00YTUwLTk4NDItY2QyZGQ5ZGVhZTEwIiwicHJvb2ZzIjoiZUp5VnpOc1NRa0FBQU5CLzhhcVpWY3VXUitSU2E1bHFpRzE2MEtJaHViUlc2dXY3aHM0SG5JdGtSR1VEcmZaTVN3cEgwbmFkb3BwNTdDSVdlRUh5R2dvODFUalYyWWFNV0JoRjVhSVBxaWZ0cUowMk9lcWhTOEptV0hKTWsva2didThQMFRQZVFmWlVIR2toR1k0UWRtbHoyTis5VVhqeWlFQmY3Unl3cFpWaHpvU3pDQUtWTC8xY2U0Qi9hNnZPdUZ4UXdOOWl6VHI5UlRQUDlhTVkweUJZN1htVWhtMWMyZGJjRHVJclhYOGQra3ZpIiwic2lnbmF0dXJlIjoiQlVVWHZ5VE9LS0hiSHBYUTMydlc5bFJzRVB2WEZsVkF5a3l2YTFIV0pLVUdMTExyV3NwMDN4aVdNWVdOclhweUJRYUhyZHdkWk5CcEp6a0dXSlowQ1EifQ",
};

const expandedDerivedJwp = {
  protected: { kid: "did:example:123#key-0", alg: "MDP+EdDSA", zip: "DEF" },
  payloads: ["Yg"],
  proof:
    "eyJyb290IjoiYzllYjU1YWU4OTk0M2Q0MDRmY2U2MzI3MTM4MTAxYzgwYjIyYzcxYmIzYTY2NmFkZTBiYWY5YTRiZmIzN2JjNiIsIm5vbmNlIjoidXJuOnV1aWQ6ZTJjYWRlMDQtMjg5Ny00YTUwLTk4NDItY2QyZGQ5ZGVhZTEwIiwicHJvb2ZzIjoiZUp4RnpMc09nakFVQU5CLzZhb0pscllYNm9aUjFDZytZMkkwRHREYkdud1ZMU2pFK08rNnVaM3A3TjhFYzZjdTFtbWMyWnZTcEV1a0ZpcWpQZ011NFNjWmNDcU5DVU9sZzVScFJnVmtraG5BanRJK3BnWWs4c3lFRW8yZlVrNHBrdmIvWER5c05iOHppcXRxWUFhT0ZjZFJXWTFhSlhoRlBvNjkvaTZQZW5YaTFJWjUzTkVwaXJNWDZYd0lEWnllWWlYV0lVTEJoc244Y3FkdXN0dld5eXA3TllsTW5XWHEyb25KNS9BRk45Zzl3Zz09Iiwic2lnbmF0dXJlIjoiQlVVWHZ5VE9LS0hiSHBYUTMydlc5bFJzRVB2WEZsVkF5a3l2YTFIV0pLVUdMTExyV3NwMDN4aVdNWVdOclhweUJRYUhyZHdkWk5CcEp6a0dXSlowQ1EifQ",
};
```
