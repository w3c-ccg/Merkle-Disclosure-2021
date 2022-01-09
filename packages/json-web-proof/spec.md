%%%
title = "Json Web Proofs for Binary Merkle Trees"
abbrev = "JWP-BMT"
ipr= "none"
area = "Internet"
workgroup = "none"
submissiontype = "IETF"
keyword = [""]

[seriesInfo]
name = "Individual-Draft"
value = "jwp-bmt-00"
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

Merkle proofs are already being used to provide certificate transparency in [@!RFC9162].

The purpose of this specification is to define a **generic** encoding of merkle audit paths that is suitable for combining with [@!RFC7515] to construct selective disclosure proofs, that are not bound to the needs of certificate transparency, and that are suitable for more generic applications such as [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) and [W3C Decentralized Identifiers](https://www.w3.org/TR/did-core/).

{mainmatter}

# Introduction

The scheme described herin features many important properties:

1. Defined deterministic nonce generation for membership proofs, to protect against second pre-image attacks.
2. Defined encoding of binary packed sets of merkle audit paths suitable for expression in JSON.
3. Defined compression of sets of audit paths to reduce data redundancy for sparse redactions under selective disclosure schemes.
4. Defined verification of merkle proofs combined with detached JWS as specified by [@!RFC7797].

These properties allow the scheme to be used in applications where privacy and data minimization techniques are desired and/or required.

This scheme is meant to expose interfaces compatible with [BBS+ Signature Scheme](https://mattrglobal.github.io/bbs-signatures-spec/).

Many of the same benefits from that scheme apply here:

> A recent emerging use case applies signature schemes in [verifiable credentials](https://www.w3.org/TR/vc-data-model/). One problem with using simple signature schemes like ECSDA or ED25519 is a holder must disclose the entire signed message and signature for verification. Circuit based logic can be applied to verify these in zero-knowledge like SNARKS or Bulletproofs with R1CS but tend to be complicated. BBS+ on the other hand adds, to verifiable credentials or any other application, the ability to do very efficient zero-knowledge proofs. A holder gains the ability to choose which claims to reveal to a relying party without the need for any additional complicated logic.

## Notational Conventions

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when they appear in this
document, are to be interpreted as described in [@!RFC2119].

## Terminology

We will rely on the general terminology defined in [@!RFC7515], [@!RFC7797] and concepts defined in [@!RFC9162].

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

Salted Member
: The hash of a member bytes and its `memberNonce` under a chosen cryptographic hash function. These values represent the leaves of a binary merkle tree that encodes membership proofs for salted members.

Binary Merkle Tree of Salted Members
: The binary merkle tree produced through concatonation, and hashing of `Salted Members`

# Overview

## K-ary Merkle Trees

We restrict this specification to Binary (2-ary) Merkle Trees.

In short, increasing the branching factor of the merkle tree above 2 does not yield the desired properties.

See [Verkle Trees](https://math.mit.edu/research/highschool/primes/materials/2018/Kuszmaul.pdf).

See [Vector Commitments and their Applications](https://eprint.iacr.org/2011/495.pdf).

See [Zero-Knowledge Sets with short proofs](https://www.iacr.org/archive/eurocrypt2008/49650430/49650430.pdf).

Vector commitment schemes are not defined in this specification,
however we believe that some similar approach using them would be worth considering in future work.

## Comparison with RFC9162

### Tree Construction

The most obvious difference is the limitations imposed on tree construction that differ from the construction of tree's used by Bitcoin.

See [RFC9162 Definition of the Merkle Tree](https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.1).

### Agility for Hash Algorithms

[@!RFC9162] refer to the IANA registry for [Hash Algorithms](https://datatracker.ietf.org/doc/html/rfc9162#section-10.2.1)

But only define support for [SHA-256](https://oidref.com/2.16.840.1.101.3.4.2.1)

### Agility for Signature Algorithms

[@!RFC9162] refer to IANA registry for [Signature Algorithms](https://datatracker.ietf.org/doc/html/rfc9162#section-10.2.2)

But only define support for a few signature algorithms:

- ecdsa_secp256r1_sha256
- ecdsa_secp256r1_sha256
- ed25519

We prefer to generalize and enable support the full range of algorithms availabe under [jose](https://www.iana.org/assignments/jose/jose.xhtml).

We believe choices regarding agility should be handled at a higher layer, but agree that restriction is a best practice.

## Comparison with BBS+ Signatures

BBS+ Signatures are in the process of being standardized.

Refer to [Editors Draft of BBS+ Signature Scheme](https://mattrglobal.github.io/bbs-signatures-spec/) for details.

At a high level, we are seeking a larger degree of agility at both the hash and digital signature layers.

## Agility for Hash Algorithms

We believe that Blake2b as defined in [@!RFC7693] is the only supported hash algorithm.

## Agility for Signature Algorithms

We believe that BLS signature over BLS12381 as defined in [Pairing-Friendly Curves](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-10), are the only supported signature scheme.

# Tree Constuction

Binary Merkle Trees are constructed via the following algorithm:

See [compute tree](https://github.com/transmute-industries/verifiable-data/blob/main/packages/merkle-proof/src/index.ts#L179)

```
let salted_members be the series defined by hashing the concatonation of each member bytes with its member nonce.
let salted_members be the first level of a binary merkle tree, where each salted member is a leaf.
for each pair of 2 leaves in the first level of the merkle tree, concatonate the leave and hash the result yielding the next first level of the merkle tree.
if the first level of the tree is odd AND its length is not 1 (the end state), promote the odd leaf to the next leve and repeat the process.
The algorithm ends when the first level of the merkle tree has length 1, its single element is the merkle root.
```

Here is a simple visualizaton of a tree constructed in this manner:

```
      h(h(h(sm0+sm1) + h(sm2+sm3)) + sm4) (merkle root)
      /                         \
    h(h(sm0+sm1) + h(sm2+sm3))  sm4 (2 siblings)
    /          \                /
   h(sm0+sm1)   h(sm2+sm3)   sm4 (3 siblings)
  /   \        /   \         /
sm0   sm1   sm2    sm3      sm4 (leaves are the base level, 5 siblings)
^     ^     ^      ^        ^
|     |     |      |        |
m0    m1    m2     m3       m4
```

Note that this tree is "unbalanced" See [Forgery Attacks on Unbalanced Binary Merkle Trees](#name-forgery-attacks-on-unbalanced-binary-merkle-trees).

Also note that this algorithm differs from the one proposed in [RFC9162](https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.1).

The reason for this difference arises from our desire to support merkle trees and proofs used by [Bitcoin](https://bitcoin.stackexchange.com/questions/69018/merkle-root-and-merkle-proofs), and our desire to encode a generic merkle proof that is not bound to "Certificate Transparency".

However, we may adjust the algorithm to match the one described in [@!RFC9162] in the future.

# Encoding

## Binary

### Merkle Audit Paths

In order to verify that member bytes are included in a merkle root, a verifier requires:

1. A nonce for the member bytes to protect against second pre-image attacks.
2. An "audit path" or "inclusion path" from the member leaf to the merkle root.

This section defines a compact binary encoding of these "member proofs" based on approaches developed by Google and others related to "Protocol Buffers".

The main feature of protocol buffers which is used is called "varint".

This approach is also refered to as [LEB128](https://en.wikipedia.org/wiki/LEB128).

This approach is also used in [Web Assembly](https://webassembly.github.io/spec/core/binary/values.html)

This approach is also used in [multiformats](https://pkg.go.dev/github.com/multiformats/go-varint).

We remain unaware of a best normative reference to provide for "protocol buffer style varints".

See this expired [internet draft for protocol buffers](https://datatracker.ietf.org/doc/html/draft-rfernando-protocol-buffers-00#page-5).

See [Google's documentation for protocol buffers](https://developers.google.com/protocol-buffers).

#### Encoding of Inclusion Paths

We describe a binary encoding of an "audit path" or "inclusion path" and a nonce, such that a verifier with a merkle root may confirm that some given "member bytes" are included in a merkle root.

We define a binary encoded "membership proof" or a given "member" bytes as follows:

numberOfAuditHashesProofs
: A positive integer encoded via `varint`, representing the size of `auditDirectionsAsBits` and `auditHashes`.

auditDirectionsAsBits
: A binary encoded bitstring representing the directions (left or right) in path from a leaf to a root in a binary merkle tree.

memberNonce
: A value derived from a cryptographic hash function and the Root Nonce. This value MUST have the same length as each Hash in `auditHashes`

auditHashes
: A series (ordered) of hashes of size determined by the cryptographic hash function chosen, (32 bytes for SHA256).

See Test Vectors for specific examples.

### Encoding Membership Proofs

We describe a binary encoding of a Root Nonce, Merkle Root, and series (order matters) of "audit path" or "inclusion paths".

These values are encoded via a convention of `varint(length of bytes) + bytes`.

This is to support hash functions of varying lengths and member proofs of varying lengths.

#### Full Disclosure

We define a `Full Disclosure` membership proof as the result of compression (under zlib v1.2.8) of the following:

rootNonce
: A value produced by the chosen cryptographic hash function applied to some source of randomness. See [Randomness considerations](#name-randomness-considerations). This value is encoded as varint (root nonce length in bytes) + root nonce bytes.

root
: A merkle root defined from a binary merkle tree composed of members derived from the hash of the member bytes and the `memberNonce`. See [Tree Construction](#name-tree-construction). This value is encoded as varint (root length in bytes) + root bytes.

membershipProofs
: A series of "membership proof" bytes, encoded under the scheme: varint (member proof length in bytes) + member proof bytes.

When decoding first the `rootNonce` and `root` are removed using varint decoding.

Then the remaining bytes are reduces by appling varint decoded to obtain the individual member proofs.

The compressed representations MUST NOT encode the original member bytes.

The order of member bytes MUST be preserved in some external data structure, in order to suppor full disclosure proof verification.

#### Selective Disclosure

We define `Selective Disclosure` the same as `Full Disclosure` with the exception that the `rootNonce`
MUST NOT be encoded in the compressed representation.

The `rootNonce` MUST be ommited in order to ensure that a selective disclosure proof does not reveal information that can be used to brute force siblings of disclosed members. This attack is also refered to as a second pre-image attack, See [Disclosure of Root Nonce](#name-disclosure-of-root-nonce).

We recommend never transmitting the full disclosure proof, and instead deriving a selective disclosure proof even for the full disclosure use case.

## Authenticated Full Disclosure Proof

In order to provide an "issuer" with the capability to provide a set of verifiable claims about a subject, a digital signature over a merkle root and some meta data can be applied.

We distinguish this data structure from a `Full Disclosure Proof` by definition.

Authenticated Full Disclosure Proof
: An encoding of a digital signature over a merkle proot and meta data, encoded next to a `Full Disclosure Proof`.

Under this scheme a verifier MUST first, verify the signature by obtaining the associated public key from the meta data.

If the signature is valid, the verifier MUST second, verify all members of the disclosed proof have a corresponding encoded member proof.

If all members have a proof and the merkle root has a signature that is verified by the public key dereferenced by from the meta data we say:

The issuer has provided a full disclosure proof for the encoded members.

In other words, the issuer claims the members are in a set, and this claim can be verified as originating from the issuer and not having been tampered with under the assumption that the issuer's signing keys have not been compromised.

For a more formal definition of digital signature verification see [@!RFC7515] and [@!RFC7797].

### JOSE

TODO: We are discussing JSON encodings of Authenticated Full Disclosure proofs [here](https://github.com/json-web-proofs/json-web-proofs/issues/15).

### COSE

TODO: We are ommiting COSE encodings until JWP is on a standards track.

## Authenticated Selective Disclosure Proof

Similar to the `Authenticated Full Disclosure Proof` we define an Authenticated Selective Disclosure by definition:

Authenticated Selective Disclosure Proof
: An encoding of a digital signature over a merkle proot and meta data, encoded next to a `Selective Disclosure Proof`.

We note that a `Selective Disclosure Proof` MUST be derived from an associated `Full Disclosure Proof`.

This derivation process omits the `rootNonce` and filter the associated `member proofs`.

We refer to the set of disclosed members proofs as:

Disclosed Member Series
: A series (order matters) of membership proofs for a given merkle root.

Redacted Member Series
: A series (order matters) of membership proofs which were present in the original `Full Disclosure Proof`, but are ommited in the `Selective Disclosure Proof`.

We note that the `Redacted Member Series` may have size 0, however the absence of the `rootNonce` still differentiates the `Authenticated Selective Disclosure Proof` from an `Authenticated Full Disclosure Proof`.

### JOSE

TODO: We are discussing JSON encodings of Authenticated Selective Disclosure proofs [here](https://github.com/json-web-proofs/json-web-proofs/issues/15).

### COSE

TODO: We are ommiting COSE encodings until JWP is on a standards track.

# Security Considerations

## Validating Public Keys

All algorithms that operate on public keys require first validating those keys.
We assume all keys are represented according to [@!RFC7517].

Implementers are warned to consider base64url padding concerns.

## Disclosure of Root Nonce

If the root nonce associated with a merkle root is disclosed, a verifier or attacker can compute adjacent membership proofs from sets of disclosed proofs.

## Forgery Attacks on Unbalanced Binary Merkle Trees

When a binary merkle tree is unbalanced (last level leaf count is not a power of 2), there is a potential for a forgery attack.

See [CVE-2012-2459](https://bitcointalk.org/?topic=102395).

We remain unable to prove that our salting approach mitigates this potential vulnerability, as such the question remains:

> does salting members before construction prevent forgery attacks on unbalanced binary merkle trees?

A note that [@!RFC9162] [constructs merkle tree's differently](https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.1).

See issue [#4](https://github.com/w3c-ccg/Merkle-Disclosure-2021/issues/4).

See issue [#3](https://github.com/w3c-ccg/Merkle-Disclosure-2021/issues/3).

## Side Channel Attacks

Implementations of the signing algorithm SHOULD protect the secret key from side-channel attacks. One method for protecting against certain side-channel attacks is ensuring that the implementation executes exactly the same sequence of instructions and performs exactly the same memory accesses, for any value of the secret key. ( this copied verbatum from [here](https://raw.githubusercontent.com/mattrglobal/bbs-signatures-spec/master/spec.md)).

## Randomness Considerations

It is recommended that the all nonces are from a trusted source of randomness AND all randomness is used for a single purpose.

For example, do not reuse randomness associated with Root Nonce for anything else.

## Choice of Hash Primitive

The disclosure proofs defined herin rely on "Merkle Audit Paths" which are built from binary merkle trees under a chose hash function.

The choice of the hash function such as SHA-256 or SHAKE-256 is out of scope for this specification.

However, at the time of publishing we recommend a cryptographic hash function with at least 256-bit security strength.

Implementers are advised to consult:

- [@!RFC8702]
- [@!RFC4634]
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

<br/>

- Algorithm Name: "ES256K+MDSHA256"
- Algorithm Description: ECDSA under Secp256k1 (bitcoin and ethereum curve) with binary merkle trees under SHA-256.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section of this document (RFC TBD)
- Algorithm Analysis Documents(s): [RFC TBD]

<br/>

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
