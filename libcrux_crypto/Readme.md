# OpenMLS libcrux crypto provider

A crypto backend for OpenMLS based on [libcrux](https://github.com/cryspen/libcrux),
implementing `openmls_traits`.

## Supported ciphersuites

The base MLS ciphersuites (`MLS_128_DHKEMX25519_...`) are always supported.

With the `draft-ietf-mls-pq-ciphersuites` feature enabled, this provider additionally
supports the following ciphersuites from
[draft-ietf-mls-pq-ciphersuites](https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/):

| Draft ID | Ciphersuite |
|----------|-------------|
| TBD1 | `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` |
| TBD2 | `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519` |
| TBD3 | `MLS_128_MLKEM768P256_AES128GCM_SHA256_P256` |
| TBD4 | `MLS_128_MLKEM768P256_AES256GCM_SHA384_P256` |
| TBD6 | `MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519` |
| TBD7 | `MLS_128_MLKEM768_AES256GCM_SHA384_P256` |
| TBD9 | `MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44` |
| TBD10 | `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65` |
| TBD11 | `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` |

These are TBD (not yet IANA-assigned) code points; this provider uses provisional
values in the MLS private-use range until real ones are registered.

### Not yet supported

| Draft ID | Ciphersuite | Blocked on |
|----------|-------------|------------|
| TBD5 | `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384` | No libcrux P-384 signing crate yet. |
| TBD8 | `MLS_192_MLKEM1024_AES256GCM_SHA384_P384` | No libcrux P-384 signing crate yet. |

TODO(pq-ciphersuites): once libcrux ships P-384 ECDSA signing, add `HpkeKemType`
support for the `MLKEM1024-P384` hybrid KEM (already implemented upstream in
the `draft-ietf-hpke-pq` HPKE provider this crate depends on) and wire up these
two ciphersuites the same way TBD3/4/7/8's P-256 counterparts are wired up here.

Separately, the pre-existing, experimental
`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` ciphersuite (unrelated to this
draft) is no longer supported by this provider: it uses an obsolete X-Wing HPKE
KEM code point (`0x004D`) that the `draft-ietf-hpke-pq`-enabled HPKE backend
this provider now depends on does not implement — only the current code point
(`0x647a`, used by TBD1/TBD2/TBD9 above) is implemented upstream.
