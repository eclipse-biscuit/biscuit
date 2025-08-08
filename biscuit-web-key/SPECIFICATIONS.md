# Biscuit web keys

A token issuer may publish public keys over HTTPS, in order to let verifying parties acquire keys
dynamically. This mechanism relies on the trust placed by the verifying parties on the owner of a
specific domain name, related to the issuer. Deciding which domain name to trust for a given
token is still the responsibility of the relying party and has to happen out-of-band.

Concretely, a domain can expose a list of public key descriptors as a JSON array on a well-known URI.

Biscuit web key sets can be referred to "bwks", which is pronounced "bivouacs".

### Biscuit web keys endpoint

The owner of `example.org` may expose a list of public key descriptors

- served over HTTPS;
- for GET requests;
- at `/.well-known/biscuit-web-keys`;
- with a JSON payload (described below) as the response body.

The response body must conform to the following schema:

```json
 {
  "$schema": "http://json-schema.org/draft-2020-12/schema#",
  "type": "array",
  "items": {
    "type": "object",
    "properties": {
      "algorithm": {
        "type": "string",
        "enum": [
          "ed25519"
        ]
      },
      "key_bytes": {
        "type": "string",
        "pattern": "^([0-9a-fA-F]{2})*$"
      },
      "key_id": {
        "type": "integer"
      },
      "issuer": {
        "type": "string"
      },
      "expires_at": {
        "type": "string",
        "format": "date-time"
      }
    },
    "required": [
      "algorithm",
      "key_bytes",
      "key_id"
    ]
  }
}
```

Additionally:

- `key_bytes` must contain an hex-encoded byte array, containing the binary encoding of the corresponding public key;
- `key_id` is mandatory and must correspond to the `rootKeyId` field set on tokens signed by the corresponding key;
- `expires_at` is optional and can provide information about the expected validity period of the
corresponding key. It is not linked to expiration checks carried with tokens and is simply intended to advertise planned key rotations;
- `issuer` is optional and can contain freeform text. It is intended to provide finer grained information about the scope, _within the trust boundary set by the domain name_.

**`key_id` and `issuer` are meant to let verifying parties choose keys within a set that they already trust. They are in no way enough to make the verifying party trust a key.**

