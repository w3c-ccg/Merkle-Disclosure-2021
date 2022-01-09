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

[[author]]
initials = "M."
surname = "Prorock"
fullname = "Michael Prorock"
#role = "editor"
organization = "mesur.io"
[author.address]
email = "mprorock@mesur.io"

%%%
.# Abstract

Merkle proofs are already being used to provide certificate transparency in [[RFC9162]].

The purpose of this specification is to define a **generic** encoding of merkle audit paths that is suitable for combining with [[RFC7515]] to construct selective disclosure proofs, that are not bound to the needs of certificate transparency, and that are suitable for more generic applications such as [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) and [W3C Decentralized Identifiers](https://www.w3.org/TR/did-core/).

{mainmatter}

# Introduction

The scheme described herin features many important properties:

1. Defined deterministic nonce generation for membership proofs, to protect against second pre-image attacks.
2. Defined encoding of binary packed sets of merkle audit paths suitable for expression in JSON.
3. Defined compression of sets of audit paths to reduce data redundancy for sparse redactions under selective disclosure schemes.
4. Defined verification of merkle proofs combined with detached JWS as specified by [[RFC7797]].

These properties allow the scheme to be used in applications where privacy and data minimization techniques are desired and/or required.

This scheme is meant to expose interfaces compatible with [BBS+ Signature Scheme](https://mattrglobal.github.io/bbs-signatures-spec/).

Many of the same benefits from that scheme apply here:

> A recent emerging use case applies signature schemes in [verifiable credentials](https://www.w3.org/TR/vc-data-model/). One problem with using simple signature schemes like ECSDA or ED25519 is a holder must disclose the entire signed message and signature for verification. Circuit based logic can be applied to verify these in zero-knowledge like SNARKS or Bulletproofs with R1CS but tend to be complicated. BBS+ on the other hand adds, to verifiable credentials or any other application, the ability to do very efficient zero-knowledge proofs. A holder gains the ability to choose which claims to reveal to a relying party without the need for any additional complicated logic.

## Notational Conventions

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when they appear in this
document, are to be interpreted as described in [@!RFC2119].

## Terminology

We will rely on the general terminology defined in [[RFC7515]], [[RFC7797]] and concepts defined in [[RFC9162]].

We introduce primarily 2 new concepts needed to generalize authenticated set membership proofs based on binary merkle trees.

The following terminology is used throughout this document:

Full Disclosure Proof
: A data structure that represents all members in a set, and all proofs of membership

Selective Disclosure Proof
: A data structure that represents a non-strict subset of a FullDisclosureProof.

Root Nonce
: A source of entropy that when combined with a suitable cryptographic hash function is sufficient to prevent brute force attacks on siblings of disclosed members.

Calculate Member Nonce
: A function for assigning nonces to members based on their order, Root Nonce, and the chosen hash function. Example provided below in typescript.

```ts
const calculateMessageNonce = (
  message: Buffer,
  index: number,
  rootNonce: Buffer,
  hash: Function
) => {
  const encodedIndex = Buffer.from(varint.encode(index));
  return hash(Buffer.concat([message, encodedIndex, rootNonce]));
};
```

# Overview

## Comparison with RFC9162

TODO

## Comparison with BBS+ Signatures

TODO

# Encoding

## Full Disclosure Proof

### Binary

#### Merkle Audit Paths

#### Sets of Merkle Audit Paths

### JOSE

### COSE

## Selective Disclosure Proof

### Binary

### JOSE

### COSE

# Security Considerations

## Validating public keys

All algorithms that operate on public keys require first validating those keys.
We assume all keys are represented according to [[RFC7517]].

Implementers are warned to consider base64url padding concerns.

## Disclosure of root nonce

If the root nonce associated with a merkle root is disclosed, a verifier or attacker can compute adjacent membership proofs from sets of disclosed proofs.

## Side channel attacks

Implementations of the signing algorithm SHOULD protect the secret key from side-channel attacks. One method for protecting against certain side-channel attacks is ensuring that the implementation executes exactly the same sequence of instructions and performs exactly the same memory accesses, for any value of the secret key. ( this copied verbatum from [here](https://raw.githubusercontent.com/mattrglobal/bbs-signatures-spec/master/spec.md)).

## Randomness considerations

It is recommended that the all nonces are from a trusted source of randomness AND all randomness is used for a single purpose.

For example, do not reuse randomness associated with Root Nonce for anything else.

## Choice of Hash Primitive

The disclosure proofs defined herin rely on "Merkle Audit Paths" which are built from binary merkle trees under a chose hash function.

The choice of the hash function such as SHA-256 or SHAKE-256 is out of scope for this specification.

However, at the time of publishing we recommend a cryptographic hash function with at least 256-bit security strength.

Implementers are advised to consult:

- [[RFC8702]]
- [[RFC4634]]
- [NIST SP 800-185](https://csrc.nist.rip/external/nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

## Choice of Signature Primitive

Alone a Full Disclosure Proof can only prove membership, and is subject to tampering.

When combined with digital signature schemes, authentication is achievable.

The choice of the signature scheme such as ES256K or EdDSA is out of scope for this specification.

Implementers are advised to consult:

- [IANA JOSE Registry](https://www.iana.org/assignments/jose/jose.xhtml)
- [FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/draft)
- [safecurves.cr.yp.to](https://safecurves.cr.yp.to/)

# IANA Considerations

The following has NOT YET been added to the "JSON Web Proof Algorithm Types" registry:

- Algorithm Name: "ES256+MDSHA256"
- Algorithm Description: ECDSA under P-256 (secp256r1) with binary merkle trees under SHA-256.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section of this document (RFC TBD)
- Algorithm Analysis Documents(s): [RFC TBD]

- Algorithm Name: "ES256K+MDSHA256"
- Algorithm Description: ECDSA under Secp256k1 (bitcoin and ethereum curve) with binary merkle trees under SHA-256.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section of this document (RFC TBD)
- Algorithm Analysis Documents(s): [RFC TBD]

- Algorithm Name: "EdDSA+MDSHA256"
- Algorithm Description: EdDSA under Ed25519 with binary merkle trees under SHA-256.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section of this document (RFC TBD)
- Algorithm Analysis Documents(s): [RFC TBD]

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
