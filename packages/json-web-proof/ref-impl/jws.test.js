const jws = require("./jws");
const header = {};
const payload = { hello: "world" };

it("secp256k1", async () => {
  const privateKeyJwk = {
    kty: "EC",
    crv: "secp256k1",
    x: "1F1NpCD4LpLFLyB331QEXRLetsYOaHN7UcVvoiFDIWE",
    y: "qZbAP6LVUozDLE_-imodZtu780YYfJ4bX1w-mLGHLvo",
    d: "Vh-iRjTZp4olbXxYibXNUq7ozeEhMQeF04HeFCKaKS0",
  };
  const signature = await jws.sign(header, payload, privateKeyJwk);
  const verified = await jws.verify(signature, privateKeyJwk);
  expect(verified).toBe(true);
});
