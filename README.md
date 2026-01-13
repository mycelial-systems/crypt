# crypt

[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/crypt/nodejs.yml?style=flat-square)](https://github.com/substrate-system/crypt/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/crypt?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/crypt)](https://packagephobia.com/result?p=@substrate-system/crypt)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)

A CLI tool and JavaScript library for creating keys and
encoding strings. Exposes a command-line interface (`crypt`) and a
Typescript API.


<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
- [Example](#example)
  * [Generate and Encode Keys](#generate-and-encode-keys)
  * [Show Help Text](#show-help-text)
- [Commands](#commands)
  * [`keys [keyType]`](#keys-keytype)
  * [`public [privateKey]`](#public-privatekey)
  * [`sign [message]`](#sign-message)
  * [`encode [output-format]`](#encode-output-format)
  * [`decode [input-format]`](#decode-input-format)
- [JS API](#js-api)
  * [Installation](#installation)
  * [Importing](#importing)
  * [`keys(options)`](#keysoptions)
  * [`derivePublicKey(privateKey, options)`](#derivepublickeyprivatekey-options)
  * [`sign(message, options)`](#signmessage-options)
  * [`encode(input, options)`](#encodeinput-options)
  * [`decode(input, options)`](#decodeinput-options)
- [Key Format](#key-format)
  * [Multikey](#multikey)
  * [Private keys](#private-keys)

<!-- tocstop -->

</details>

## Install

Install globally:

```sh
npm i -g @substrate-system/crypt
```

Or install locally, and run with `npx`:

```sh
npm i -D @substrate-system/crypt
npx crypt keys
```

## Example

### Generate and Encode Keys

For **Ed25519** keys, this will print a JSON string with
`{ publicKey, privateKey }` to `stdout`. By default (format `raw`):
- `publicKey` is in multikey format
- `privateKey` is the base64url-encoded seed

For **X25519** keys (used for key exchange/ECDH), output is the same as Ed25519:
- `publicKey` is base64url-encoded
- `privateKey` is the base64url-encoded seed

For **RSA** keys, the private key is written to a file (requires `-o` option)
and the public key is printed to `stdout` in multikey format.

You can pass in a different encoding to use for the output with
the `-f` or `--format` option.

```sh
# Generate Ed25519 keypair (outputs both keys to stdout)
npx crypt keys

# Generate X25519 keypair for key exchange
npx crypt keys x25519

# Generate RSA keypair, write private key to file
npx crypt keys rsa -o private.pem

# Generate RSA keypair in JWK format (outputs both keys to stdout)
npx crypt keys rsa -f jwk

# Derive a public key from a private key
npx crypt public <private-key> --type ed25519 --input base64url --format json

# Sign a message
npx crypt sign "my document" -k <private-key-seed>

# Sign from stdin
echo "my document" | npx crypt sign -k <private-key-seed>

# Convert between encoding formats via stdin
echo "Hello World" | npx crypt encode base64
# => SGVsbG8gV29ybGQ

echo "SGVsbG8gV29ybGQ" | npx crypt encode utf8 -i base64
# => Hello World

echo "SGVsbG8gV29ybGQ" | npx crypt encode hex -i base64
# => 48656c6c6f20576f726c64
```


### Show Help Text

```sh
npx crypt --help

# Show help for a specific command
npx crypt keys --help
npx crypt encode --help
```

---


## Commands

### `keys [keyType]`

Generate a new cryptographic keypair, by default `ed25519`.

**Ed25519 keys** (signing): Output is a JSON string of `{ publicKey, privateKey }`
to stdout, by default (`-f raw`). The public key is in multikey format and
the private key is a base64url-encoded seed. Use `-f jwk` for JWK format.
If `-o` is specified, the private key is written to the file and only the
public key is printed to stdout.

**X25519 keys** (key exchange/ECDH): Similar to Ed25519, outputs
`{ publicKey, privateKey }` to stdout. By default (`-f raw`), both keys are
base64url-encoded. Use `-f jwk` for JWK format.

**RSA keys** (signing): Requires `-o` option to specify output file for the private key
(in PKCS#8 PEM format), unless using `-f jwk` which outputs both keys as
JSON to stdout.

#### Arguments

* `keyType` - The key type to use (default: `ed25519`)
  - `ed25519` - Ed25519 elliptic curve (signing)
  - `x25519` - X25519 elliptic curve (key exchange/ECDH)
  - `rsa` - RSA-PSS 2048-bit (signing)

#### Options

* `-f, --format` - Output format (default: `raw`)
  - `raw` - **(default)** For Ed25519: public key in multikey format,
    private key as base64url-encoded seed. For X25519: both keys as
    base64url-encoded strings. For RSA: requires `-o` option.
  - `jwk` - JSON Web Key format (outputs private key JWK,
    which includes public key in `x` field for Ed25519 and X25519)

* `-o, --output` - Output file for private key
  - **Required for RSA** (unless using `-f jwk`)
  - Optional for Ed25519 and X25519
    (if specified, private key goes to file instead of stdout)
  - RSA private keys are written as PKCS#8 PEM format
  - Ed25519 and X25519 private keys are written as base64url-encoded seed (default)
    or JWK format (if using `-f jwk`)

* `-u, --use` - Key usage for RSA keys (default: `sign`)
  - `sign` - **(default)** Generate RSA-PSS key for signing
  - `exchange` - Generate RSA-OAEP key for encryption/key exchange
  - Only applies to RSA keys; ignored for Ed25519 and X25519

#### `keys` Example

```sh
# Generate Ed25519 keypair (default: raw format)
npx crypt keys
# => {"publicKey":"z6Mk...", "privateKey":"mZ5t7zw8D..."}
# (publicKey is multikey format, privateKey is base64url-encoded seed)

# Generate Ed25519 keypair in JWK format
npx crypt keys -f jwk
# => {"key_ops":["sign"],"ext":true,"crv":"Ed25519","d":"...","x":"...","kty":"OKP","alg":"Ed25519"}
# (Returns private key JWK; public key is in the 'x' field)

# Generate Ed25519 keypair, save private key to file
npx crypt keys -o private.txt
# => {"publicKey":"z6Mk..."}
# (private.txt contains the base64url-encoded seed)

# Generate X25519 keypair for key exchange (default: raw format)
npx crypt keys x25519
# => {"publicKey":"B1UIJS3JEVkjr7uP1E1JWQ...","privateKey":"WCHnh8mcwxZ89Urp_i-F..."}
# (both keys are base64url-encoded)

# Generate X25519 keypair in JWK format
npx crypt keys x25519 -f jwk
# => {"key_ops":["deriveKey","deriveBits"],"ext":true,"crv":"X25519","d":"...","x":"...","kty":"OKP"}
# (Returns private key JWK; public key is in the 'x' field)

# Generate RSA signing keypair, save private key to file as PEM
npx crypt keys rsa -o private.pem
# => {"publicKey":"z5Tc..."}
# (private.pem contains PKCS#8 PEM format for RSA-PSS)

# Generate RSA encryption keypair with --use exchange
npx crypt keys rsa -f jwk -u exchange
# => {...JWK with private key...}
# (Returns private key JWK for RSA-OAEP)

# Generate RSA keypair in JWK format (signing by default)
npx crypt keys rsa -f jwk
# => {...JWK with private key...}
# (Returns private key JWK; public key components are included)
```

---

### `public [privateKey]`

Derive a public key from a private key. Supports Ed25519, X25519, RSA,
and secp256k1 (k256) keys.

#### Arguments

* `privateKey` - The private key to derive the public key from (required)
  - For Ed25519/X25519/k256: base64url-encoded seed or private key (32 bytes)
  - For RSA: PEM-formatted PKCS#8 private key

#### Options

* `-t, --type` - **(required)** The key type
  - `ed25519` - Ed25519 elliptic curve
  - `x25519` - X25519 elliptic curve
  - `rsa` - RSA key
  - `k256` - secp256k1 elliptic curve

* `-i, --input` - Input format for the private key (default: `hex`)
  - `hex` - **(default)** Hexadecimal encoding
  - `base64` - Standard base64 encoding
  - `base64url` - Base64url encoding (no padding)

* `-f, --format` - Output format (default: `json`)
  - `json` - **(default)** JSON object with `{ publicKey, keyType }`.
    `publicKey` is encoded in DID format.
  - `hex` - Hexadecimal encoding of raw public key bytes
  - `did` - DID format string (base58btc encoded, + `'did:key:'` prefix)
  - `base64url` - Base64url encoding of raw public key bytes
  - `base64` - Standard base64 encoding of raw public key bytes

#### `public` Example

```sh
# Generate a keypair first
npx crypt keys
# => {"publicKey":"z6Mk...","privateKey":"PAjfFB2OvkWOGpO9iLqMujY8YucqHriHEtcdo4GhQDM"}

# Derive the public key from the private key (JSON output)
npx crypt public PAjfFB2OvkWOGpO9iLqMujY8YucqHriHEtcdo4GhQDM --type ed25519 --input base64url --format json
# => {"publicKey":"z6MkoUHWDKfrsX2vpLaTTsMdLgCDFMzt4EJdZeTXQjbSPnsZ","keyType":"ed25519"}

# Derive public key with hex output
npx crypt public PAjfFB2OvkWOGpO9iLqMujY8YucqHriHEtcdo4GhQDM --type ed25519 --input base64url --format hex
# => 85fc69b01232c576f559bb7a58bc445d27f1d4ee81c8abc62365e9cd97520e08

# Derive k256 (secp256k1) public key
npx crypt keys k256
# => {"publicKey":"z6Du...","privateKey":"QsNnw8ZPGa4trwZeGBD7a_3gvfHI_32JCfFM1sfWZrA"}
npx crypt public QsNnw8ZPGa4trwZeGBD7a_3gvfHI_32JCfFM1sfWZrA --type k256 --input base64url --format json
# => {"publicKey":"z6Du2tMh3uXpN2ECugDAERcEuKmohcq6DqPkWakmsP9Wx3Ey","keyType":"k256"}

# Derive X25519 public key
npx crypt keys x25519
# => {"publicKey":"jlWUipLpjNR_eDr7H_dBkLgtKQiY1zKMGMtC0bxyR0Q","privateKey":"kPF-xy_ZdTqUqRH6bLOXktRUDDCLUuI8gqMl-zNXG1o"}
npx crypt public kPF-xy_ZdTqUqRH6bLOXktRUDDCLUuI8gqMl-zNXG1o --type x25519 --input base64url --format base64url
# => jlWUipLpjNR_eDr7H_dBkLgtKQiY1zKMGMtC0bxyR0Q
```

---

### `sign [message]`

Sign a message with an Ed25519 private key. The message can be provided as
a positional argument or read from stdin.

#### Arguments

* `message` - The message to sign (optional if using stdin)
  - If omitted, the message will be read from stdin
  - If provided as an argument, that takes precedence over stdin

#### Options

* `-k, --key` - **(required)** Private key seed (base64url-encoded)
  - The private key seed as output by `crypt keys` in raw format
  - This is the 'd' field from an Ed25519 JWK

#### `sign` Example

```sh
# Generate a keypair first
npx crypt keys
# => {"publicKey":"z6Mk...","privateKey":"k7s0h9nK5oqRd4ip..."}

# Sign a message using positional argument
npx crypt sign "my signed document" -k k7s0h9nK5oqRd4ip_K8ow2RXZ4p3B5Mp3hguz7G9CMI
# => jLYPhT1LAckU3WrcXlAPf4eaklfk8qTDyBf1otgqmr7Fx-YATTrZrLrlHYvNyl0EU5SF6URiKJtkyjeRGNe9AA

# Sign a message from stdin
echo "my signed document" | npx crypt sign -k k7s0h9nK5oqRd4ip_K8ow2RXZ4p3B5Mp3hguz7G9CMI
# => jLYPhT1LAckU3WrcXlAPf4eaklfk8qTDyBf1otgqmr7Fx-YATTrZrLrlHYvNyl0EU5SF6URiKJtkyjeRGNe9AA

# Sign a file
cat document.txt | npx crypt sign -k k7s0h9nK5oqRd4ip_K8ow2RXZ4p3B5Mp3hguz7G9CMI

# Complete workflow: generate keys and sign
PRIVATE_KEY=$(npx crypt keys | jq -r .privateKey)
echo "important message" | npx crypt sign -k $PRIVATE_KEY
```

The signature is output as a base64url-encoded string
(Ed25519 signatures are 64 bytes, encoded as 86 characters).

---

### `encode [output-format]`

Convert a string from one encoding format to another. Reads input from stdin.

#### Arguments

* `output-format` - The desired output format (default: `base58btc`)
  - `base58btc`, `base64`, `hex`, `base64url`, `utf8`, `ascii`

#### Options

* `-i, --input-format` - The format of the input string (default: `utf8`)
  - `base64`, `hex`, `base64url`, `base58btc`, `utf8`, `ascii`

#### `encode` Example

```sh
# Encode UTF-8 text to base58btc (default)
echo "Hello World" | npx crypt encode

# Encode UTF-8 to base64
echo "Hello World" | npx crypt encode base64

# Convert base64 to hex
echo "SGVsbG8gV29ybGQ=" | npx crypt encode hex -i base64

# Convert hex to base58btc
echo "48656c6c6f" | npx crypt encode base58btc -i hex

# Convert base64 to utf8
echo "SGVsbG8gV29ybGQ=" | npx crypt encode utf8 -i base64
# => Hello World

# Pipe between commands (publicKey is in multikey format)
npx crypt keys | jq -r .publicKey | npx crypt encode hex -i multi

# convert "multikey" format to hex format
echo "z6MkiLr..." | npx crypt encode hex -i multi
```

---

### `decode [input-format]`

Decode a string from a given encoding format to UTF-8. Reads input from stdin.

#### Arguments

* `input-format` - The format of the input string (default: `base64`)
  - `base64`, `base64pad`, `hex`, `base64url`, `base58btc`, `ascii`

#### `decode` Example

```sh
# Decode base64 to UTF-8 (default)
echo "SGVsbG8gV29ybGQ=" | npx crypt decode

# Decode base64pad to UTF-8
echo "SGVsbG8gV29ybGQ=" | npx crypt decode base64pad
# => 'Hello World'

# Decode hex to UTF-8
echo "48656c6c6f20576f726c64" | npx crypt decode hex

# Decode base58btc to UTF-8
echo "JxF12TrwUP45BMd" | npx crypt decode base58btc
```

---

## JS API

This package exposes a JavaScript API too.

### Installation

```sh
npm i -S @substrate-system/crypt
```

### Importing

```js
import { keys, derivePublicKey, sign, encode, decode } from '@substrate-system/crypt'

// Or import everything
import * as crypt from '@substrate-system/crypt'
```

### `keys(options)`

Generate a new cryptographic keypair.

```ts
async function keys (args:{
    keyType?:'ed25519'|'x25519'|'rsa',
    format?:'raw'|'jwk',
    use?:'sign'|'exchange'
} = {}):Promise<{
    publicKey:string|object,
    privateKey?:string|object,
    privateKeyPem?:string
}>
```

#### Parameters

- `options` (object, optional):
  * `keyType` (`ed25519`, `rsa` or `x25519`; default: `ed25519`)
  * `format` (`'raw' | 'jwk'`, default: `'raw'`) - Output format
  * `use` (`'sign' | 'exchange'`, default: `'sign'`) - Key usage for RSA keys
    - `'sign'` - Generate RSA-PSS key for signing
    - `'exchange'` - Generate RSA-OAEP key for encryption/key exchange
    - Ignored for Ed25519 and X25519 keys
  * `useMultibase` (boolean, default: `false`) - Add multibase prefix
    (currently not functional for multikey format)

#### Return value

- For `raw` format Ed25519/X25519: `{ publicKey: string, privateKey: string }`
- For `raw` format RSA: `{ publicKey: string, privateKeyPem: string }`
- For `jwk` format: Returns the JWK object directly

**Example:**

```js
import { keys } from '@substrate-system/crypt'

// Generate Ed25519 keypair (default)
const keypair = await keys()
console.log(keypair.publicKey)  // z6Mk... (multikey format)
console.log(keypair.privateKey)  // base64url-encoded seed

// Generate X25519 keypair
const x25519Keys = await keys({ keyType: 'x25519' })

// Generate RSA signing keypair in JWK format
const rsaJwk = await keys({ keyType: 'rsa', format: 'jwk' })

// Generate RSA encryption keypair
const rsaEncryptJwk = await keys({ keyType: 'rsa', format: 'jwk', use: 'exchange' })
```

### `derivePublicKey(privateKey, options)`

```ts
async function derivePublicKey (
    privateKeyInput:string,
    opts:{
        keyType:'ed25519'|'x25519'|'rsa'|'k256',
        inputFormat?:'hex'|'base64'|'base64url',
        outputFormat?:'json'|'hex'|'base64url'|'base64'
    }
):Promise<string|object>
```

Derive a public key from a private key. Supports Ed25519, X25519, RSA, and secp256k1 (k256) keys.

#### Parameters

- `privateKeyInput` (string) - The private key to derive from
  * For Ed25519/X25519/k256: base64url-encoded seed or private key (32 bytes)
  * For RSA: PEM-formatted PKCS#8 private key string
- `opts` (object):
  * `keyType` (`'ed25519'|'x25519'|'rsa'|'k256'`, required) - The type of key
  * `inputFormat` (`'hex'|'base64'|'base64url'`, default: `'hex'`) - Format of the private key input
  * `outputFormat` (`'json'|'hex'|'base64url'|'base64'`, default: `'json'`) - Output format

#### Return value

- For `json` format: `{ publicKey: string, keyType: string }`
  * `publicKey` is in multikey format for Ed25519/RSA/k256, base64url for X25519
- For `hex`, `base64url`, or `base64` formats: Returns the raw public key bytes in the requested encoding

**Example:**

```js
import { keys, derivePublicKey } from '@substrate-system/crypt'

// Generate an Ed25519 keypair
const keypair = await keys()
console.log(keypair.privateKey)  // PAjfFB2OvkWOGpO9iLqMujY8YucqHriHEtcdo4GhQDM

// Derive the public key from the private key
const result = await derivePublicKey(keypair.privateKey, {
  keyType: 'ed25519',
  inputFormat: 'base64url',
  outputFormat: 'json'
})
console.log(result.publicKey)  // z6MkoUHWDKfrsX2vpLaTTsMdLgCDFMzt4EJdZeTXQjbSPnsZ
console.log(result.keyType)    // ed25519

// Get raw hex output
const hexPublicKey = await derivePublicKey(keypair.privateKey, {
  keyType: 'ed25519',
  inputFormat: 'base64url',
  outputFormat: 'hex'
})
console.log(hexPublicKey)  // 85fc69b01232c576f559bb7a58bc445d27f1d4ee81c8abc62365e9cd97520e08

// Derive k256 (secp256k1) public key
const k256Keys = await keys({ keyType: 'k256' })
const k256Public = await derivePublicKey(k256Keys.privateKey, {
  keyType: 'k256',
  inputFormat: 'base64url',
  outputFormat: 'json'
})
console.log(k256Public.publicKey)  // z6Du... (multikey format)

// Derive X25519 public key
const x25519Keys = await keys({ keyType: 'x25519' })
const x25519Public = await derivePublicKey(x25519Keys.privateKey, {
  keyType: 'x25519',
  inputFormat: 'base64url',
  outputFormat: 'base64url'
})
console.log(x25519Public)  // Base64url-encoded public key
```

### `sign(message, options)`

```ts
async function sign (
    message:string,
    options:{ key:string }
):Promise<string>
```

Sign a message with a private key. Supports both Ed25519 and RSA keys.

#### Parameters
- `message` (string) - The message to sign
- `options` (object):
  * `key` (string, required) - Private key in one of these formats:
    - **Ed25519**: base64url-encoded seed
    - **RSA**: PEM-encoded private key (PKCS#8 format)

#### Returns

Base64url-encoded signature.

#### Example

```js
import { keys, sign } from '@substrate-system/crypt'

// Sign with Ed25519 key
const ed25519Keypair = await keys()
const ed25519Sig = await sign('Hello World', { key: ed25519Keypair.privateKey })
console.log(ed25519Sig)  // Base64url-encoded signature

// Sign with RSA key
const rsaKeypair = await keys({ keyType: 'rsa' })
const rsaSig = await sign('Hello World', { key: rsaKeypair.privateKeyPem })
console.log(rsaSig)  // Base64url-encoded signature
```

### `encode(input, options)`

Convert a string from one encoding format to another.

```ts
async function encode (
    input:string,
    options:{
        inputFormat?:u.SupportedEncodings|'multi',
        outputFormat:u.SupportedEncodings|'multi',
        useMultibase?:boolean,
        keyType?:'ed25519'|'rsa'
    }
):Promise<string>
```

#### Parameters
- `input` (string) - The input string to encode
- `options` (object):
  * `inputFormat` (`u.SupportedEncodings|'multi'`, default: `'utf8'`)
  * `outputFormat` (`u.SupportedEncodings|'multi'`, required) - Output format
  * `useMultibase` (boolean, default: `false`) - Add multibase prefix
  * `keyType` (`'ed25519'|'rsa'`, optional) - Required if output is `'multi'`

Supported encodings: `'base64'`, `'hex'`, `'base64url'`, `'base58btc'`,
`'utf8'`, `'ascii'`, `'multi'`

#### Returns

The encoded string

#### Example

```js
import { encode } from '@substrate-system/crypt'

// Encode UTF-8 to base64
const encoded = await encode('Hello World', {
  inputFormat: 'utf8',
  outputFormat: 'base64'
})

// Convert hex to multikey format
const multikey = await encode('1234...', {
  inputFormat: 'hex',
  outputFormat: 'multi',
  keyType: 'ed25519'
})
```

### `decode(input, options)`

Decode a string from a given format to UTF-8.

```ts
async function decode (
  input:string,
  options:{ inputFormat:u.SupportedEncodings }
):Promise<string>
```

#### Parameters

- `input` (string) - The input string to decode
- `options` (object):
  * `inputFormat` (`u.SupportedEncodings`, required) - Input format

#### Returns

The decoded UTF-8 string

#### Example

```js
import { decode } from '@substrate-system/crypt'

const decoded = await decode('SGVsbG8gV29ybGQ=', {
  inputFormat: 'base64'
})
console.log(decoded) // 'Hello World'
```

---

## Key Format

### Multikey

This uses [Multikey format](https://www.w3.org/TR/cid-1.0/#Multikey) strings.
[Multikey format](https://www.w3.org/TR/cid-1.0/#Multikey), is
a generic, self-describing,
[multicodec-based](https://www.w3.org/TR/cid-1.0/#multibase-0)
public key encoding.

```ts
import { base58btc } from 'multiformats/bases/base58'
import * as varint from "multiformats/src/varint"

// Suppose you have a raw public-key Buffer/Uint8Array
const rawKeyBytes = /* ... */

// --- helper: varint-encoded multicodec prefix for ed25519-pub ---
// multicodec code for ed25519-pub is 0xED (237).
// varint encoding for 237 is two bytes: 0xED 0x01
const ED25519_MULTICODEC_VARINT = Uint8Array.from([0xed, 0x01])
const out = new Uint8Array(ED25519_MULTICODEC_VARINT.length + rawPubKey.length)
out.set(ED25519_MULTICODEC_VARINT, 0)
out.set(rawKeyBytes, ED25519_MULTICODEC_VARINT.length)

// base58btc (multibase) encode
// multiformats' base58btc.encode typically returns a string that already
// uses the 'z'
let encoded = base58btc.encode(out)
encoded = encoded.startsWith('z') ? encoded : 'z' + encoded

// This yields something like "z6Mk…", same style as in the DID doc
console.log(encoded)

/**
 * Decode a Multikey multibase string (ed25519-pub) back to raw key bytes.
 * Returns an object { algCode, rawKey } where algCode is the multicodec
 * numeric code.
 */
function decodeMultikey (multibaseStr):{ } {
  // Accept with/without leading 'z' — multiformats will accept
  // without the explicit 'z' only if decoder used directly.
  const cleaned = (multibaseStr.startsWith('z') ?
    multibaseStr :
    'z' + multibaseStr)
  const decoded = base58btc.decode(cleaned)  // returns Uint8Array

  // read varint (we know ed25519 varint is two bytes: 0xed 0x01)
  // robust approach: parse varint; here we handle single or two-byte
  // varints for small values
  let i = 0
  let code = 0
  let shift = 0
  while (i < decoded.length) {
    const b = decoded[i++]
    code |= (b & 0x7f) << shift
    if ((b & 0x80) === 0) break
    shift += 7
  }
  const rawKey = decoded.slice(i)  // remainder is the raw key bytes
  return { multicodec: code, rawKey }
}
```

### Private keys

Private keys are either a "raw" 32 byte string, or JWK encoded, or PEM format
for RSA.
