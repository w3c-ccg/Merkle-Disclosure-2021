%%%
title = "Json Web Proof Merkle Disclosure Token"
abbrev = "JWP-MDT"
ipr= "none"
area = "Internet"
workgroup = "none"
submissiontype = "IETF"
keyword = [""]

[seriesInfo]
name = "Individual-Draft"
value = "jwp-mdt-00"
status = "informational"

[[author]]
initials = "O."
surname = "Steele"
fullname = "Orie Steele"
#role = "editor"
organization = "Transmute"
[author.address]
email = "orie@transmute.industries"
%%%
.# Abstract

Merkleproofs have been around for a long time, but there has never been a standardd JSON encoding for them.

{mainmatter}

# Introduction

Summary of merkle proofs

Challenges with proof size

This document describes the Json Web Proof Merkle Disclosure Token.
An encoding for merkle proofs inspired by JWT.

The scheme features many important properties:

1. Deterministic nonce generation for membership proofs.
2. Encoding merkle root and related proof data use JWA.
3. Compressing membership proofs
4. Verifying membership proofs

These properties allow the scheme to be used in applications where privacy and data minimization techniques are desired and/or required.

This scheme is meant to expose interfaces compatible with [BBS+ Signature Scheme](https://mattrglobal.github.io/bbs-signatures-spec/). Many of the same benefits from that scheme apply here:

> A recent emerging use case applies signature schemes in [verifiable credentials](https://www.w3.org/TR/vc-data-model/). One problem with using simple signature schemes like ECSDA or ED25519 is a holder must disclose the entire signed message and signature for verification. Circuit based logic can be applied to verify these in zero-knowledge like SNARKS or Bulletproofs with R1CS but tend to be complicated. BBS+ on the other hand adds, to verifiable credentials or any other application, the ability to do very efficient zero-knowledge proofs. A holder gains the ability to choose which claims to reveal to a relying party without the need for any additional complicated logic.

## Notational Conventions

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when they appear in this
document, are to be interpreted as described in [@!RFC2119].

## Terminology

The following terminology is used throughout this document:

SK
: The secret key for the signature scheme.

PK
: The public key for the signature scheme.

U
: The set of messages to be signed or verified.

M
: The set of messages to be signed or verified paired with their deterministic nonce.

protected
: The protected header to be signed by the JWA scheme.

payload
: The protected payload to be signed by the JWA scheme.

signature
: The digital signature output.

nonce
: A cryptographic nonce

path
: A set membership proof, represented as a path in a merkle proof from a leaf to a root.

proofs
: A set of membership proofs, encoded as JSON.

compressedProofs
: `proofs` compressed and encoded as base64url.

calculateMessageNonce(message, index, rootNonce) -> nonce
: The funtion that takes a message, index and rootNonce and assigns a deterministic nonce for the message.

```
const calculateMessageNonce = (
  message: string,
  index: number,
  rootNonce: string
) => {
  return sha256(message + index + rootNonce);
};
```

verification
: A boolean representing a proof verification, success as true, failure as false.

compressProofs(proofs) -> compressedProofs
: The function that takes JSON encoded path based membership proofs and returns a compressed representation of them. Inverse of `expandProofs`.

expandProofs(compressedProofs) -> proofs
: The function that takes a compressed representation of membership proofs and return them in JSON. Inverse of `compressProofs`.

getProofs(messages, rootNonce) -> proofs
: The function that takes a set of messages and a rootNonce and produces a merkle root and membership proofs for each message.

deriveProofs(disclosureIndexes, proofs, messages, rootNonce) -> compressedProofs
: The function that takes a set of disclosureIndexes, proofs, messages and a rootNonce and produces compressedProofs represenetation of the messages indentified by disclosureIndexes.

verifyProofs(messages, proofs, root) -> verification
: The function that takes a set messages, proofs and a merkle root, and returns true when all messages have a membership proof that is true, and false otherwise.

sha256
: The SHA-256 hash function defined in [@!RFC6234].

# Overview

//TODO

## Organization of this document

This document is organized as follows:

- The remainder of this section defines terminology and the high-level API.

- Section 2 defines primitive operations used in the merkle proof signature scheme. These operations MUST NOT be used alone.

- Section 3 defines JSON encoding requirements.

- Section 4 defines security considerations.

- Section 5 defines the references.

- Section 6 defines test vectors.

## Comparison with BBS+ Signatures

Not exactly the same thing, but probably better than comparing to vanilla JWA.

# Core operations

This section defines core operations used by the schemes defined in Section 3. These operations MUST NOT be used except as described in that section.

## Parameters

The core operations in this section depend on several parameters:

- A JWA and JWS, plus associated functionality given in Section 1.4.
- H, a hash function that MUST be a secure cryptographic hash function, e.g. SHA-256.

## KeyValidate

KeyValidate checks if the public key is valid.

As an optimization, implementations MAY cache the result of KeyValidate in order to avoid unnecessarily repeating validation for known keys.

```
result = KeyValidate(PK)
```

Inputs:

- PK, a public key

Outputs:

- result, either VALID or INVALID

Procedure:

// TODO

## Generate Proof

Generate proof computes set membership proofs and a signature from SK, over a vector of messages.

```
{ root, nonce, proofs, signature } = generateProof((message\[i\],...,message\[L\]), SK)
```

Inputs:

- message\[i\],...,message\[L\], octet strings
- SK, a secret key

Outputs:

- root, an octet string
- nonce, an octet string
- proofs, an octet string
- signature, an octet string

Procedure:

// TODO

## Derive Proof

Derive proof transforms the output of generate proof filtering the set membership proofs
to match the intended messages to be disclosed and applying the nonce algorithm.
This process is also referred to as generating a selective disclosure proof.

```
{ root, proofs, signature } = deriveProof(
  (disclosureIndexes[i],...,disclosureIndexes[L]),
  (message[i],...,message[L]),
  (proof[i],...,proof[L]),
  root,
  nonce,
  signature
)
```

Inputs:

- disclosureIndexes\[i\],...,disclosureIndexes\[L\], octet integer.
- message\[i\],...,message\[L\], octet strings.
- proof\[i\],...,proof\[L\], octet strings.
- root, octet string.
- nonce, octet string.
- signature, octet string.

Outputs:

- root, octet string, unchanged by function.
- proofs, octet string.
- signature, octet string, unchanged by function.

Procedure:

//TODO

## Verify Proof

Verify checks that a proof is valid for the octet string messages under the public key.

```
verification = Verify((message[i],...,message[L]), (proof[i],...,proof[L]), root, signature, PK)
```

Inputs:

- message\[i\],...,message\[L\], octet strings.
- proof\[i\],...,proof\[L\], octet strings.
- root, octet string.
- signature, octet string.
- PK, a public key

Outputs:

- verification, either VALID or INVALID.

Procedure:

// TODO

# Security Considerations

## Validating public keys

All algorithms in Section 2 that operate on public keys require first validating those keys.
For the sign, verify and proof schemes, the use of KeyValidate is REQUIRED.

## Disclosure of root nonce

If the root nonc associatd with a merkle root is disclosed, a verifier or attacker can compute adjcacent membership proofs from sets of disclosed proofs.

## Side channel attacks

Implementations of the signing algorithm SHOULD protect the secret key from side-channel attacks. One method for protecting against certain side-channel attacks is ensuring that the implementation executes exactly the same sequence of instructions and performs exactly the same memory accesses, for any value of the secret key. ( this copied verbatum form [here](https://raw.githubusercontent.com/mattrglobal/bbs-signatures-spec/master/spec.md)).

## Randomness considerations

It is recommended that the all nonces are from a trusted source of randomness.

## Choice of Signature Primitive

TODO: comment on JOSE / COSE.

# IANA Considerations

This document does not make any requests of IANA.

TODO:

Request for JOSE and COSE...:

- alg: MDP+ES256+JP
- alg: MDP+ES384+JP
- etc...

# Appendix

- JSON Web Signature (JWS) - [RFC7515][spec-jws]
- JSON Web Encryption (JWE) - [RFC7516][spec-jwe]
- JSON Web Key (JWK) - [RFC7517][spec-jwk]
- JSON Web Algorithms (JWA) - [RFC7518][spec-jwa]
- JSON Web Token (JWT) - [RFC7519][spec-jwt]
- JSON Web Key Thumbprint - [RFC7638][spec-thumbprint]
- JWS Unencoded Payload Option - [RFC7797][spec-b64]
- CFRG Elliptic Curve ECDH and Signatures - [RFC8037][spec-okp]

[spec-b64]: https://tools.ietf.org/html/rfc7797
[spec-cookbook]: https://tools.ietf.org/html/rfc7520
[spec-jwa]: https://tools.ietf.org/html/rfc7518
[spec-jwe]: https://tools.ietf.org/html/rfc7516
[spec-jwk]: https://tools.ietf.org/html/rfc7517
[spec-jws]: https://tools.ietf.org/html/rfc7515
[spec-jwt]: https://tools.ietf.org/html/rfc7519
[spec-okp]: https://tools.ietf.org/html/rfc8037
[spec-secp256k1]: https://tools.ietf.org/html/rfc8812
[spec-thumbprint]: https://tools.ietf.org/html/rfc7638

## Test Vectors

//TODO

{backmatter}
