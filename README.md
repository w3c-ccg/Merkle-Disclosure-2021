# Merkle-Disclosure-2021

Allow systems to share some information that some original system approved without sharing all information that original system originally approved.

The scope this work item proposal is limited to a linked data proof suite specification (in html), suitable for registry in the https://github.com/w3c-ccg/ld-cryptosuite-registry.

## Include Link to Abstract or Draft

- https://transmute-industries.github.io/merkle-disclosure-proof-2021/
- https://github.com/OR13/jwp-mdt

(This repository includes proof of concept code, which we are not intending to develop further at the W3C CCG).

## List Owners

@OR13
@mprorock

## Work Item Questions

> Answer the following questions in order to document how you are meeting the requirements for a new work item at the W3C Credentials Community Group. Please note if this work item supports the Silicon Valley Innovation program or another government or private sector project.

### 1. Explain what you are trying to do using no jargon or acronyms.

Allow systems to share some information that some original system approved without sharing all information that original system originally approved.

### 2. How is it done today, and what are the limits of the current practice?

https://github.com/w3c-ccg/ldp-bbs2020

- relies on RDF and LD Processing for object normalization and multi message signatures
- relies on unregistered (IANA) or not NIST approved curve bls12381
- relies on draft standard for bbs+ signatures with bls12381
- draft standard for bbs+ signatures relies on unregistered (IANA) or not NIST approved hash function blake2b

https://github.com/decentralized-identity/crypto-wg/blob/main/work_items/json_web_proof.md

- brand new work item
- (currently) limited to ZKP multi message schemes like BBS+ with BLS12381.

We hope to participate in the DIF work item for JWP as well, see comments on this proposal:

https://github.com/w3c-ccg/community/issues/204#issuecomment-903169800

### 3. What is new in your approach and why do you think it will be successful?

- normalization is pluggable, compatible with JSON-LD but not requiring it.
- Json Web Signatures are an international standard RFC7515
- building blocks are widely available in multiple languages (sha256 merkle proofs, json web signatures, json pointer, urdna2015)

### 4. How are you involving participants from multiple skill sets and global locations in this work item? (Skill sets: technical, design, product, marketing, anthropological, and UX. Global locations: the Americas, APAC, Europe, Middle East.)

We'll try to use GitHub and the mailing list as much as possible so that meeting attendance is not required for participation.

### 5. What actions are you taking to make this work item accessible to a non-technical audience?

We're limiting the work item to a specification that describes existing standards and building blocks, but those standards and building blocks are pretty technical.

The scope of the work item is limited to a document, which attempts to use language and metaphors that enable non-technical audience members to follow along, without understand how to build a cryptographically secure hash function, perform RDF Data Set normalization, or design a digital signature scheme... all of which require significant technical background to do well.

Since this work item just treats these concepts as black boxes, we hope non technical members will be able to focus on and contribute to the "what" and not the "how".

In particular, we have an informative section dedicated to use cases for selective disclosure.

We'll also be directing tangentially related conversations to the appropriate location, such as the DIF Applied Cryptography Working Group, the W3C VC Working Group, the various standards bodies maintaining the specifications this suite is built on or supports, JSON Pointer, JSON, JSON Web Signatures, JSON-LD, Verifiable Credentials, Decentralized Identifiers.

We'll be encouraging heavy use of citations and discouraging significant language addressing concepts that are better explained by these existing standards, this should help encourage folks to focus on the shared mental model provided by those standards, and limit the complexity of issues and pull requests that modify the html of the specification.
