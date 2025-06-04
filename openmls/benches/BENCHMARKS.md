## libcrux provider

### MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519

|                          | Median (ns)               |
| ------------------------ | ------------------------- |
| KeyPackage create bundle | 131699.63522588523 (+41%) |
| Create a welcome message | 398898.12625418056 (+24%) |
| Join a group             | 337742.20283723244 (+22%) |
| Create a commit          | 296304.89166666666 (+28%) |

### MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519

|                          | Median (ns)        |
| ------------------------ | ------------------ |
| KeyPackage create bundle | 214897.08252108714 |
| Create a welcome message | 698736.72          |
| Join a group             | 544471.4704036635  |
| Create a commit          | 535049.6666666666  |

## Rust crypto org provider

### MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
|                          | Median (ns)        |
| ------------------------ | ------------------ |
| KeyPackage create bundle | 92994.09118840579  |
| Create a welcome message | 320738.42698259186 |
| Join a group             | 276701.10714285716 |
| Create a commit          | 231436.10869565216 |

### MLS_128_DHKEMP256_AES128GCM_SHA256_P256

|                          | Median (ns)       |
| ------------------------ | ----------------- |
| KeyPackage create bundle | 763718.0534883721 |
| Create a welcome message | 1546551.5         |
| Join a group             | 1155185.846153846 |
| Create a commit          | 1099256.15        |

### MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

|                          | Median (ns)        |
| ------------------------ | ------------------ |
| KeyPackage create bundle | 93977.1410638298   |
| Create a welcome message | 314389.69917485956 |
| Join a group             | 275012.4433306056  |
| Create a commit          | 230306.07692307694 |
