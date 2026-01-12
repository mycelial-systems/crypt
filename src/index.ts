import * as u from 'uint8arrays'
import * as multikey from '@substrate-system/multikey'
import { publicKeyToDid } from '@substrate-system/keys/crypto'
import { createPrivateKey, sign as cryptoSign, constants as cryptoConstants } from 'node:crypto'
import { webcrypto } from '@substrate-system/one-webcrypto'

/**
 * Encode a string in one format to a different format.
 * Core API function that returns the encoded string.
 */
export async function encode (
    input:string,
    options:{
        inputFormat?:u.SupportedEncodings|'multi',
        outputFormat:u.SupportedEncodings|'multi',
        keyType?:'ed25519'|'rsa'
    }
):Promise<string> {
    const inputFormat = options.inputFormat || 'utf8'
    const outputFormat = options.outputFormat
    // const useMultibase = options.useMultibase || false
    const keyType = options.keyType

    let bytes:Uint8Array

    // Handle multibase input format
    if (inputFormat === 'multi') {
        const { format, data } = detectMultibaseFormat(input)
        bytes = u.fromString(data, format)
    } else {
        // First decode from the input format to Uint8Array
        bytes = u.fromString(input, inputFormat)
    }

    if (outputFormat === 'multi') {
        // Strip multicodec prefix, since `formatOutput` will add it
        // Ed25519 varint prefix: [237, 1] (0xED, 0x01)
        // RSA varint prefix: [133, 36] (0x85, 0x24) encoding of 0x1205
        let keyBytes = bytes
        if (bytes.length > 2) {
            // Check for Ed25519 multicodec prefix (varint: 0xED, 0x01)
            if (bytes[0] === 0xed && bytes[1] === 0x01) {
                keyBytes = bytes.slice(2)
            } else if (bytes[0] === 0x85 && bytes[1] === 0x24) {
                // Check for RSA multicodec prefix (varint: 0x85, 0x24)
                keyBytes = bytes.slice(2)
            }
        }
        // For encode command, we're not dealing with SPKI format
        return formatOutput(keyBytes, 'multi', keyType, false)
    }

    // Then encode to the output format
    const output = u.toString(bytes, outputFormat)

    return output
}

/**
 * Generate a new keypair.
 * Core API function that returns keypair data.
 * For Ed25519: By default (format 'raw'), private keys are exported as
 *              base64url-encoded seeds, public keys as multikey format.
 *              Can use format 'jwk' for JWK format.
 * For X25519: Same as Ed25519 - private keys are exported as base64url-encoded
 *             seeds, public keys as base64url-encoded keys.
 *             Can use format 'jwk' for JWK format.
 * For RSA: Private keys are exported as PKCS#8 PEM or JWK,
 *          public keys as multikey format or JWK.
 *          Use 'sign' for RSA-PSS (signing), 'exchange' for RSA-OAEP (encryption).
 */
export async function keys (args:{
    keyType?:'ed25519'|'x25519'|'rsa'|'k256',
    format?:'raw'|'jwk',
    use?:'sign'|'exchange'
} = {}):Promise<{
    publicKey:string|object,
    privateKey?:string|object,
    privateKeyPem?:string
}> {
    const keyType = args.keyType || 'ed25519'
    const publicFormat = args.format || 'raw'
    const use = args.use || 'sign'

    if (keyType === 'ed25519') {
        const keypair = await webcrypto.subtle.generateKey(
            {
                name: 'Ed25519',
                namedCurve: 'Ed25519'
            },
            true,
            ['sign', 'verify']
        )

        const privateKeyJwk = await webcrypto.subtle.exportKey(
            'jwk',
            keypair.privateKey
        )

        if (publicFormat === 'jwk') {
            // Return private key JWK directly
            // (which contains public key in 'x' field)
            return privateKeyJwk as any
        } else {
            // For 'raw' format, use multikey for public key
            const publicKey = await webcrypto.subtle.exportKey(
                'raw',
                keypair.publicKey
            )
            const publicKeyFormatted = await formatOutput(
                new Uint8Array(publicKey),
                'multi',
                'ed25519',
                true
            )

            // Extract seed from JWK 'd' field (already base64url encoded)
            if (!privateKeyJwk.d) {
                throw new Error('Private key JWK missing "d" field')
            }

            return {
                publicKey: publicKeyFormatted,
                privateKey: privateKeyJwk.d
            }
        }
    } else if (keyType === 'x25519') {
        const keypair = await webcrypto.subtle.generateKey(
            {
                name: 'X25519',
                namedCurve: 'X25519'
            },
            true,
            ['deriveKey', 'deriveBits']
        )

        const privateKeyJwk = await webcrypto.subtle.exportKey(
            'jwk',
            keypair.privateKey
        )

        if (publicFormat === 'jwk') {
            // Return private key JWK directly
            // (which contains public key in 'x' field)
            return privateKeyJwk as any
        } else {
            // For 'raw' format, export keys as base64url
            const publicKey = await webcrypto.subtle.exportKey(
                'raw',
                keypair.publicKey
            )
            const publicKeyEncoded = u.toString(
                new Uint8Array(publicKey),
                'base64url'
            )

            // Extract seed from JWK 'd' field (already base64url encoded)
            if (!privateKeyJwk.d) {
                throw new Error('Private key JWK missing "d" field')
            }

            return {
                publicKey: publicKeyEncoded,
                privateKey: privateKeyJwk.d
            }
        }
    } else if (keyType === 'rsa') {
        const algorithmName = use === 'exchange' ? 'RSA-OAEP' : 'RSA-PSS'
        const keyUsages:(
            'encrypt' | 'decrypt' | 'sign' | 'verify'
        )[] = use === 'exchange' ?
            ['encrypt', 'decrypt'] :
            ['sign', 'verify']

        const keypair = await webcrypto.subtle.generateKey(
            {
                name: algorithmName,
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            keyUsages
        )

        if (publicFormat === 'jwk') {
            // Return private key JWK directly (contains public key components)
            const privateKey = await webcrypto.subtle.exportKey(
                'jwk',
                keypair.privateKey
            )

            return privateKey as any
        } else {
            // For 'raw' format, export as PKCS#8 PEM and multikey
            const publicKey = await webcrypto.subtle.exportKey(
                'spki',
                keypair.publicKey
            )
            const privateKey = await webcrypto.subtle.exportKey(
                'pkcs8',
                keypair.privateKey
            )

            const pem = pkcs8ToPem(new Uint8Array(privateKey))
            const publicKeyFormatted = await formatOutput(
                new Uint8Array(publicKey),
                'multi',
                'rsa',
                true
            )

            return {
                publicKey: publicKeyFormatted,
                privateKeyPem: pem
            }
        }
    } else if (keyType === 'k256') {
        // secp256k1 - use Node.js crypto (not available in WebCrypto)
        const { generateKeyPairSync } = await import('node:crypto')

        const { privateKey, publicKey } = generateKeyPairSync('ec', {
            namedCurve: 'secp256k1'
        })

        if (publicFormat === 'jwk') {
            // Return private key JWK directly
            const privateKeyJwk = privateKey.export({ format: 'jwk' })
            return privateKeyJwk as any
        } else {
            // For 'raw' format, export keys as base64url
            // Export private key as JWK to get the 'd' value
            const privateKeyJwk = privateKey.export({ format: 'jwk' }) as {
                d?: string;
                x?: string;
                y?: string;
            }

            if (!privateKeyJwk.d) {
                throw new Error('Private key JWK missing "d" field')
            }

            // Export public key in compressed format (33 bytes)
            // SEC1 compressed format: 0x02/0x03 prefix + x coordinate
            const publicKeyRaw = publicKey.export({
                format: 'der',
                type: 'spki'
            })

            // Extract raw public key from SPKI DER format and compress it
            const publicKeyCompressed = extractCompressedSecp256k1Key(publicKeyRaw)
            const publicKeyEncoded = u.toString(publicKeyCompressed, 'base64url')

            return {
                publicKey: publicKeyEncoded,
                privateKey: privateKeyJwk.d
            }
        }
    }

    throw new Error(`Unsupported keyType: ${keyType}`)
}

/**
 * Format output with multibase prefix for base58btc, DID, or multi format.
 * Note: 'raw' format should be handled before calling this function
 * (converted to 'multi' for public keys).
 */
export async function formatOutput (
    bytes:Uint8Array,
    format:u.SupportedEncodings|'did'|'multi'|'raw',
    keyType?:'ed25519'|'rsa',
    isPublicKey = false
):Promise<string> {
    // 'raw' format for public keys should use multikey format
    if (format === 'raw') {
        format = 'multi'
    }

    if (format === 'did') {
        // For DID format, we need raw key bytes
        let keyBytes = bytes
        if (keyType === 'rsa' && isPublicKey) {
            // Extract raw key from SPKI format
            keyBytes = extractRawRsaKey(bytes)
        }
        return await publicKeyToDid(keyBytes, keyType)
    }

    if (format === 'multi') {
        // Multikey format: use the multikey package
        let keyBytes = bytes
        if (keyType === 'rsa' && isPublicKey) {
            // Extract raw key from SPKI format
            keyBytes = extractRawRsaKey(bytes)
        }
        if (!keyType) {
            throw new Error('keyType is required for multikey format')
        }
        return multikey.encode(keyBytes, keyType)
    }

    const encoded = u.toString(bytes, format as u.SupportedEncodings)

    return encoded
}

/**
 * Convert PKCS#8 DER bytes to PEM format.
 */
function pkcs8ToPem (der:Uint8Array):string {
    const base64 = u.toString(der, 'base64pad')
    const pem = [
        '-----BEGIN PRIVATE KEY-----',
        ...base64.match(/.{1,64}/g) || [],
        '-----END PRIVATE KEY-----'
    ].join('\n')
    return pem
}

/**
 * Extract raw RSA public key from SPKI format.
 * SPKI structure contains algorithm identifier and other metadata.
 * We need just the raw key bytes for multikey encoding.
 */
function extractRawRsaKey (spkiBytes:Uint8Array):Uint8Array {
    // For RSA keys in SPKI format, the raw key is embedded in the BIT STRING
    // We need to parse the ASN.1 structure to extract it
    // This is a simplified parser that works for standard RSA SPKI keys

    // Skip to the BIT STRING that contains the actual public key
    // SPKI format: SEQUENCE { algorithm, publicKey BIT STRING }
    let offset = 0

    // Skip SEQUENCE tag and length
    if (spkiBytes[offset] !== 0x30) {
        throw new Error('Invalid SPKI format: expected SEQUENCE')
    }
    offset++

    // Skip length bytes (can be 1-4 bytes)
    const firstLengthByte = spkiBytes[offset++]
    if (firstLengthByte & 0x80) {
        const lengthOfLength = firstLengthByte & 0x7f
        offset += lengthOfLength
    }

    // Skip algorithm identifier SEQUENCE
    if (spkiBytes[offset] !== 0x30) {
        throw new Error('Invalid SPKI format: expected algorithm SEQUENCE')
    }
    offset++
    const algLengthByte = spkiBytes[offset++]
    let algLength = algLengthByte
    if (algLengthByte & 0x80) {
        const lengthOfLength = algLengthByte & 0x7f
        algLength = 0
        for (let i = 0; i < lengthOfLength; i++) {
            algLength = (algLength << 8) | spkiBytes[offset++]
        }
    }
    offset += algLength

    // Now we're at the BIT STRING containing the public key
    if (spkiBytes[offset] !== 0x03) {
        throw new Error('Invalid SPKI format: expected BIT STRING')
    }
    offset++

    // Read BIT STRING length
    const bitStringLengthByte = spkiBytes[offset++]
    let bitStringLength = bitStringLengthByte
    if (bitStringLengthByte & 0x80) {
        const lengthOfLength = bitStringLengthByte & 0x7f
        bitStringLength = 0
        for (let i = 0; i < lengthOfLength; i++) {
            bitStringLength = (bitStringLength << 8) | spkiBytes[offset++]
        }
    }

    // Skip the "number of unused bits" byte (should be 0)
    offset++

    // The remaining bytes are the actual RSA public key in PKCS#1 format
    return spkiBytes.slice(offset)
}

/**
 * Extract and compress a secp256k1 public key from SPKI DER format.
 * Returns 33-byte compressed format (0x02/0x03 prefix + x coordinate).
 */
function extractCompressedSecp256k1Key (spkiDer:Buffer):Uint8Array {
    // SPKI for EC keys contains:
    // SEQUENCE {
    //   SEQUENCE { algorithm OID, curve OID }
    //   BIT STRING { uncompressed point: 04 || x || y }
    // }
    // For secp256k1, the uncompressed point is 65 bytes (1 + 32 + 32)

    // Find the BIT STRING containing the public key
    // It starts with 0x03 (BIT STRING tag) followed by length
    let offset = 0

    // Skip outer SEQUENCE
    if (spkiDer[offset] !== 0x30) {
        throw new Error('Invalid SPKI format: expected SEQUENCE')
    }
    offset++

    // Skip length
    if (spkiDer[offset] & 0x80) {
        offset += 1 + (spkiDer[offset] & 0x7f)
    } else {
        offset++
    }

    // Skip algorithm SEQUENCE
    if (spkiDer[offset] !== 0x30) {
        throw new Error('Invalid SPKI format: expected algorithm SEQUENCE')
    }
    offset++

    const algLength = spkiDer[offset]
    if (algLength & 0x80) {
        const lengthOfLength = algLength & 0x7f
        let len = 0
        for (let i = 0; i < lengthOfLength; i++) {
            len = (len << 8) | spkiDer[offset + 1 + i]
        }
        offset += 1 + lengthOfLength + len
    } else {
        offset += 1 + algLength
    }

    // Now at BIT STRING
    if (spkiDer[offset] !== 0x03) {
        throw new Error('Invalid SPKI format: expected BIT STRING')
    }
    offset++

    // Skip BIT STRING length
    if (spkiDer[offset] & 0x80) {
        offset += 1 + (spkiDer[offset] & 0x7f)
    } else {
        offset++
    }

    // Skip unused bits count (should be 0)
    offset++

    // Now we should have the uncompressed point: 04 || x (32 bytes) || y (32 bytes)
    if (spkiDer[offset] !== 0x04) {
        throw new Error('Expected uncompressed point format (0x04)')
    }

    const x = spkiDer.subarray(offset + 1, offset + 33)
    const y = spkiDer.subarray(offset + 33, offset + 65)

    // Compress: prefix is 0x02 if y is even, 0x03 if y is odd
    const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03
    const compressed = new Uint8Array(33)
    compressed[0] = prefix
    compressed.set(x, 1)

    return compressed
}

/**
 * Get the multibase prefix for a given encoding format.
 * @see https://github.com/multiformats/multibase
 */
export function getMultibasePrefix (format:u.SupportedEncodings):string {
    const prefixes:Record<string, string> = {
        base64: 'm',
        base64pad: 'M',
        base64url: 'u',
        base64urlpad: 'U',
        base58btc: 'z',
        hex: 'f',
        ascii: '',
        utf8: ''
    }
    return prefixes[format] || ''
}

/**
 * Detect the encoding format from a multibase prefix.
 * @see https://github.com/multiformats/multibase
 */
function detectMultibaseFormat (input:string):{
    format:u.SupportedEncodings,
    data:string
} {
    if (input.length === 0) {
        throw new Error('Empty input string')
    }

    const prefix = input[0]
    const data = input.slice(1)

    const formatMap:Record<string, u.SupportedEncodings> = {
        m: 'base64',
        M: 'base64pad',
        u: 'base64url',
        U: 'base64urlpad',
        z: 'base58btc',
        f: 'hex'
    }

    const format = formatMap[prefix]
    if (!format) {
        throw new Error(`Unknown multibase prefix: ${prefix}`)
    }

    return { format, data }
}

/**
 * Decode a string from a given format to UTF-8.
 * Core API function that returns the decoded string.
 */
export async function decode (
    input:string,
    options:{ inputFormat:u.SupportedEncodings }
):Promise<string> {
    const inputFormat = options.inputFormat

    // Decode from the input format to Uint8Array
    const bytes = u.fromString(input, inputFormat)

    // Convert to UTF-8 string
    return u.toString(bytes, 'utf8')
}

/**
 * Sign a message with a private key.
 * Core API function that returns the signature.
 * Supports both Ed25519 (base64url-encoded seed) and RSA (PEM format) keys.
 */
export async function sign (
    message:string,
    options:{ key:string }
):Promise<string> {
    const privateKeyInput = options.key

    // Validate that message is not empty
    if (!message || message.length === 0) {
        throw new Error('Message cannot be empty')
    }

    // Convert message to bytes
    const messageBytes = u.fromString(message, 'utf8')

    // Detect key type based on format
    let privateKey:ReturnType<typeof createPrivateKey>
    let signature:Buffer

    if (privateKeyInput.startsWith('-----BEGIN')) {
        // RSA key in PEM format (PKCS#8)
        privateKey = createPrivateKey(privateKeyInput)

        // Sign using RSA-PSS with SHA-256
        signature = cryptoSign('sha256', messageBytes, {
            key: privateKey,
            padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
            saltLength: cryptoConstants.RSA_PSS_SALTLEN_AUTO
        })
    } else {
        // Ed25519 key (base64url-encoded seed)
        // Create a JWK with just the private key component
        // Node.js crypto can derive the public key from the private key
        const privateKeyJwk = {
            kty: 'OKP',
            crv: 'Ed25519',
            d: privateKeyInput,
            x: '' // Will be derived by Node.js
        }

        // Create a KeyObject from the JWK
        privateKey = createPrivateKey({
            key: privateKeyJwk,
            format: 'jwk'
        })

        // Sign the message using Node.js crypto
        signature = cryptoSign(null, messageBytes, privateKey)
    }

    // Convert signature to base64url
    return u.toString(
        new Uint8Array(signature),
        'base64url'
    )
}
