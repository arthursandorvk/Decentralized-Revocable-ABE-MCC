# Security Notes

## Threat model (summary — see the paper for formal definitions and proofs)

- **Attribute authorities** are mutually distrusting and may be individually
  compromised; security holds as long as the corruption threshold of the
  decentralized setting is respected.
- **The cloud server** is honest-but-curious: it performs aided decryption
  faithfully but must learn nothing about plaintexts or user secret keys.
- **Revocation** must be immediate and collusion-resistant: a revoked user
  colluding with the server must not decrypt ciphertexts created after
  revocation.
- **Key exposure**: leakage of the server-side transformation material must not
  reveal the user's final decryption secret.

## Known limitations of this prototype

- Not constant-time; do not deploy against timing adversaries.
- No side-channel countermeasures.
- Parameter validation is minimal.

Report security issues privately to the corresponding author, not via public
issues.
