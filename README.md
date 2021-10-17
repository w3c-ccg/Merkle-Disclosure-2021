# Json Web Proof Merkle Disclosure Token

[Latest Draft](https://or13.github.io/jwp-mdt/)

Json Web Proof Merkle Disclosure Token is a bucket for
organizing merkle proof encodings for JOSE and COSE.

The spec does way to much in one place currently,
hopefully we can find other IETF specs to delegate to.

## Contributing

The main specification is written in the markdown, however to preview the changes you have made in the final format, the following steps can be followed.

The tool `markdown2rfc` is used to convert the raw markdown representation to both an HTML and XML format. In order to run this tool you must have [docker](https://www.docker.com/) installed.

### Updating Docs

Update `spec.md` file with your desired changes.

Run the following to compile the new txt into the output HTML.

`./scripts/build-html.sh`

### See Also

- [bbs-signatures-spec](https://github.com/mattrglobal/bbs-signatures-spec)
