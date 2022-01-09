# Convert markdown to XML and HTML versions
docker run -v `pwd`:/data or13/markdown2rfc spec.md || exit 1

# Delete XML version
rm jwp-bmt-00.xml

# Rename the HTML version for hosting with GH pages
mv jwp-bmt-00.html ../../docs/jwp/index.html

