import { test } from '@substrate-system/tapzero'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import * as u from 'uint8arrays'
import { sign, encode, decode, keys } from '../src/index.js'

const CLI_PATH = join(process.cwd(), 'dist', 'cli.js')

// Test the `keys` command
test('`keys` generates Ed25519 keypair by default in raw format', async t => {
    const result = await runCLI(['keys'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    t.ok(output.publicKey, 'should have publicKey property')
    t.ok(output.privateKey, 'should have privateKey property')
    t.ok(output.publicKey.startsWith('z6Mk'),
        'public key should be in multikey format (z6Mk prefix for Ed25519)')
    t.ok(typeof output.privateKey === 'string',
        'private key should be a base64url string')
    t.ok(!output.privateKey.includes('{'),
        'private key should not be a JSON object')
})

test('keys command generates Ed25519 keypair in JWK format', async t => {
    const result = await runCLI(['keys', 'ed25519', '-f', 'jwk'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    // Should return just the private key JWK (which contains public key in 'x')
    t.equal(output.kty, 'OKP', 'should have kty OKP')
    t.equal(output.crv, 'Ed25519', 'should have crv Ed25519')
    t.ok(output.x, 'should have x (public key) component')
    t.ok(output.d, 'should have d (private key) component')
    t.ok(!output.publicKey, 'should not have separate publicKey field')
    t.ok(!output.privateKey, 'should not have separate privateKey field')
})

test('keys command generates RSA keypair with JWK format', async t => {
    const result = await runCLI(['keys', 'rsa', '-f', 'jwk'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    // Should return just the private key JWK
    t.equal(output.kty, 'RSA', 'should be RSA JWK')
    t.ok(output.d, 'should have d (private exponent)')
    t.ok(output.n, 'should have n (modulus)')
    t.ok(output.e, 'should have e (public exponent)')
    t.ok(output.p, 'should have p (first prime)')
    t.ok(output.q, 'should have q (second prime)')
    t.ok(!output.publicKey, 'should not have separate publicKey field')
    t.ok(!output.privateKey, 'should not have separate privateKey field')
})

test('keys command generates RSA encryption keypair with --use exchange',
    async t => {
        const result = await runCLI(['keys', 'rsa', '-f', 'jwk', '-u', 'exchange'])

        t.equal(result.code, 0, 'command should exit with code 0')

        const output = JSON.parse(result.stdout.trim())

        // Should return RSA JWK for encryption
        t.equal(output.kty, 'RSA', 'should be RSA JWK')
        t.ok(output.d, 'should have d (private exponent)')
        t.ok(output.n, 'should have n (modulus)')
        t.ok(output.e, 'should have e (public exponent)')
    })

test('`keys` generates X25519 keypair by default in raw format', async t => {
    const result = await runCLI(['keys', 'x25519'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    t.ok(output.publicKey, 'should have publicKey property')
    t.ok(output.privateKey, 'should have privateKey property')
    t.ok(typeof output.publicKey === 'string',
        'public key should be a string')
    t.ok(typeof output.privateKey === 'string',
        'private key should be a base64url string')
    t.ok(!output.privateKey.includes('{'),
        'private key should not be a JSON object')
})

test('keys command generates X25519 keypair in JWK format', async t => {
    const result = await runCLI(['keys', 'x25519', '-f', 'jwk'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    // Should return just the private key JWK (which contains public key in 'x')
    t.equal(output.kty, 'OKP', 'should have kty OKP')
    t.equal(output.crv, 'X25519', 'should have crv X25519')
    t.ok(output.x, 'should have x (public key) component')
    t.ok(output.d, 'should have d (private key) component')
    t.ok(!output.publicKey, 'should not have separate publicKey field')
    t.ok(!output.privateKey, 'should not have separate privateKey field')
})

test('`keys` generates k256 (secp256k1) keypair in raw format', async t => {
    const result = await runCLI(['keys', 'k256'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    t.ok(output.publicKey, 'should have publicKey property')
    t.ok(output.privateKey, 'should have privateKey property')
    t.ok(typeof output.publicKey === 'string',
        'public key should be a string')
    t.ok(typeof output.privateKey === 'string',
        'private key should be a base64url string')
    t.ok(!output.privateKey.includes('{'),
        'private key should not be a JSON object')

    // Verify public key is in multikey format (starts with 'z')
    t.ok(output.publicKey.startsWith('z'),
        'k256 public key should be in multikey format (z prefix for base58btc)')

    // Decode multikey to verify it's 34 bytes
    // (1 byte multicodec + 33 bytes compressed key)
    const multikey = output.publicKey.slice(1) // Remove 'z' prefix
    const decoded = u.fromString(multikey, 'base58btc')
    t.equal(decoded.length, 34,
        'decoded multikey should be 34 bytes (1 multicodec + 33 compressed key)')
    t.equal(decoded[0], 0xe7, 'first byte should be 0xe7 (secp256k1 multicodec)')
    // Second byte should be 0x02 or 0x03 (compressed key prefix)
    t.ok(decoded[1] === 0x02 || decoded[1] === 0x03,
        'compressed public key should start with 0x02 or 0x03')
})

test('keys command generates k256 keypair in JWK format', async t => {
    const result = await runCLI(['keys', 'k256', '-f', 'jwk'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    // Should return just the private key JWK (contains public key components)
    t.equal(output.kty, 'EC', 'should have kty EC')
    t.equal(output.crv, 'secp256k1', 'should have crv secp256k1')
    t.ok(output.x, 'should have x (public key x coordinate) component')
    t.ok(output.y, 'should have y (public key y coordinate) component')
    t.ok(output.d, 'should have d (private key) component')
    t.ok(!output.publicKey, 'should not have separate publicKey field')
    t.ok(!output.privateKey, 'should not have separate privateKey field')
})

test('k256 raw has multikey public key & base64url private key', async t => {
    const result = await runCLI(['keys', 'k256'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    // Public key should be in multikey format
    t.ok(typeof output.publicKey === 'string',
        'public key should be a string')
    t.ok(output.publicKey.startsWith('z'),
        'public key should be multikey format with z prefix')

    // Private key should be base64url encoded string
    t.ok(typeof output.privateKey === 'string',
        'private key should be a string')
    t.ok(/^[A-Za-z0-9_-]+$/.test(output.privateKey),
        'private key should be valid base64url (no padding)')
})

test('keys command rejects invalid format', async t => {
    const result = await runCLI(['keys', 'ed25519', '--format', 'hex'])

    t.ok(result.code !== 0, 'should exit with non-zero code for invalid format')
    t.ok(
        (
            result.stderr.includes('Invalid values') ||
            result.stderr.includes('Choices')
        ),
        'should show error about invalid format choice'
    )
})

test('keys command shows help with --help flag', async t => {
    const result = await runCLI(['keys', '--help'])

    t.equal(result.code, 0, 'help command should exit with code 0')
    t.ok(result.stdout.includes('Create a new keypair'),
        'should show command description')
    t.ok(result.stdout.toLowerCase().includes('type'),
        'should mention type parameter')
    t.ok(result.stdout.includes('format'),
        'should mention format option')
    t.ok(result.stdout.includes('raw'),
        'should mention raw format')
    t.ok(result.stdout.includes('jwk'),
        'should mention jwk format')
})

test('Ed25519 raw has multikey public key & base64url private key', async t => {
    const result = await runCLI(['keys', 'ed25519'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    // Public key should be multikey format
    t.ok(output.publicKey.startsWith('z6Mk'),
        'public key should be multikey format with z6Mk prefix')

    // Private key should be base64url encoded string
    t.ok(typeof output.privateKey === 'string',
        'private key should be a string')
    t.ok(/^[A-Za-z0-9_-]+$/.test(output.privateKey),
        'private key should be valid base64url (no padding)')
})

// Test the `encode` command
test('encode command converts UTF-8 to base64', async t => {
    const input = 'Hello World'
    const result = await runCLIWithStdin(['encode', 'base64'], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'utf8'), 'base64')

    t.equal(output, expected, 'should correctly encode UTF-8 to base64')
})

test('encode command converts UTF-8 to base64url by default', async t => {
    const input = 'Hello World'
    const result = await runCLIWithStdin(['encode'], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'utf8'), 'base64url')

    t.equal(output, expected,
        'should correctly encode UTF-8 to base64url by default')
})

test('encode command converts base64 to hex', async t => {
    const input = 'SGVsbG8gV29ybGQ='
    const result = await runCLIWithStdin([
        'encode',
        'hex',
        '--input-format',
        'base64'
    ], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'base64'), 'hex')

    t.equal(output, expected, 'should correctly convert base64 to hex')
})

test('encode command converts hex to base58btc', async t => {
    const input = '48656c6c6f'
    const result = await runCLIWithStdin([
        'encode',
        'base58btc',
        '-i',
        'hex'
    ], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'hex'), 'base58btc')

    t.equal(output, expected, 'should correctly convert hex to base58btc')
})

test('encode command converts base64url to hex', async t => {
    const input = 'SGVsbG8gV29ybGQ'
    const result = await runCLIWithStdin([
        'encode',
        'hex',
        '--input-format',
        'base64url'
    ], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'base64url'), 'hex')

    t.equal(output, expected,
        'should correctly convert base64url to hex')
})

test('encode command shows help with --help flag', async t => {
    const result = await runCLI(['encode', '--help'])

    t.equal(result.code, 0, 'help command should exit with code 0')
    t.ok(result.stdout.includes('Encode a string'),
        'should show command description')
    t.ok(result.stdout.includes('input'),
        'should mention input parameter')
    t.ok(result.stdout.includes('output-format'),
        'should mention output-format parameter')
    t.ok(result.stdout.includes('input-format'),
        'should mention input-format option')
})

// Test the `decode` command
test('decode command decodes base64 to UTF-8 by default', async t => {
    const input = 'SGVsbG8gV29ybGQ='
    const result = await runCLIWithStdin(['decode'], input)

    t.equal(result.code, 0, 'command should exit with code 0')
    t.equal(result.stdout.trim(), 'Hello World',
        'should correctly decode base64 to UTF-8')
})

test('decode command decodes hex to UTF-8', async t => {
    const input = '48656c6c6f20576f726c64'
    const result = await runCLIWithStdin(['decode', 'hex'], input)

    t.equal(result.code, 0, 'command should exit with code 0')
    t.equal(result.stdout.trim(), 'Hello World',
        'should correctly decode hex to UTF-8')
})

test('decode command decodes base58btc to UTF-8', async t => {
    const input = 'JxF12TrwUP45BMd'
    const result = await runCLIWithStdin(['decode', 'base58btc'], input)

    t.equal(result.code, 0, 'command should exit with code 0')
    t.equal(result.stdout.trim(), 'Hello World',
        'should correctly decode base58btc to UTF-8')
})

test('decode command decodes base64url to UTF-8', async t => {
    const input = 'SGVsbG8gV29ybGQ'
    const result = await runCLIWithStdin(['decode', 'base64url'], input)

    t.equal(result.code, 0, 'command should exit with code 0')
    t.equal(result.stdout.trim(), 'Hello World',
        'should correctly decode base64url to UTF-8')
})

test('decode command decodes base64pad to UTF-8', async t => {
    const input = 'SGVsbG8gV29ybGQ='
    const result = await runCLIWithStdin(['decode', 'base64pad'], input)

    t.equal(result.code, 0, 'command should exit with code 0')
    t.equal(result.stdout.trim(), 'Hello World',
        'should correctly decode base64pad to UTF-8')
})

test('decode command shows help with --help flag', async t => {
    const result = await runCLI(['decode', '--help'])

    t.equal(result.code, 0, 'help command should exit with code 0')
    t.ok(result.stdout.includes('Decode a string'),
        'should show command description')
    t.ok(result.stdout.includes('input-format'),
        'should mention input-format parameter')
})

// General CLI behavior
test('CLI shows error when called without arguments', async t => {
    const result = await runCLI([])

    t.ok(result.code !== 0,
        'should exit with non-zero code when no command provided')
    t.ok(result.stderr.includes('You must provide a command'),
        'should show message about needing a command')
})

test('CLI shows help with --help flag', async t => {
    const result = await runCLI(['--help'])

    t.equal(result.code, 0, 'help command should exit with code 0')
    t.ok(result.stdout.includes('keys'), 'should list keys command')
    t.ok(result.stdout.includes('encode'), 'should list encode command')
})

// Test multibase input format
test('encode command handles multibase input with -i multi', async t => {
    // Create a multibase-encoded string manually (base64 with 'm' prefix)
    const input = 'Hello World'
    const base64 = u.toString(u.fromString(input, 'utf8'), 'base64')
    const multibaseString = 'm' + base64

    // Decode it using -i multi
    const resultDecode = await runCLIWithStdin(
        ['encode', 'hex', '-i', 'multi'],
        multibaseString
    )

    t.equal(resultDecode.code, 0, 'multibase decode should exit with code 0')

    const hexOutput = resultDecode.stdout.trim()
    const expected = u.toString(u.fromString(input, 'utf8'), 'hex')

    t.equal(hexOutput, expected, 'should correctly decode multibase input')
})

test('encode command handles base58btc multibase input', async t => {
    const input = 'zJxF12TrwUP45BMd'
    const result = await runCLIWithStdin(['encode', 'hex', '-i', 'multi'], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = '48656c6c6f20576f726c64'

    t.equal(output, expected,
        'should correctly decode base58btc multibase to hex')
})

test('encode command handles hex multibase input', async t => {
    const input = 'f48656c6c6f20576f726c64'
    const result = await runCLIWithStdin(['encode', 'utf8', '-i', 'multi'], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()

    t.equal(output,
        'Hello World', 'should correctly decode hex multibase to utf8')
})

test('encode command handles multikey format input', async t => {
    // Generate a multikey using raw format (which outputs multikey for public key)
    const keyResult = await runCLI(['keys', 'ed25519'])
    t.equal(keyResult.code, 0, 'keys command should exit with code 0')

    const keyOutput = JSON.parse(keyResult.stdout.trim())
    const multikey = keyOutput.publicKey

    // Convert multikey to hex using -i multi
    const result = await runCLIWithStdin(
        ['encode', 'hex', '-i', 'multi'],
        multikey
    )

    t.equal(result.code, 0, 'encode command should exit with code 0')

    const hexOutput = result.stdout.trim()

    // The hex output should start with the Ed25519 multicodec prefix (ed01)
    t.ok(hexOutput.startsWith('ed01'),
        'converted multikey should start with ed01 multicodec prefix')
})

test('encode command converts hex to multi format with key type', async t => {
    // Sample hex string representing an Ed25519 public key (32 bytes)
    const input = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
    const result = await runCLIWithStdin([
        'encode',
        'multi',
        '-i',
        'hex',
        '--type',
        'ed25519'
    ], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()

    // Multi format output for Ed25519 should start with z6Mk
    t.ok(output.startsWith('z6Mk'),
        'Ed25519 multikey format should start with z6Mk prefix')
})

test('encode command requires --type when output is multi', async t => {
    const input = '48656c6c6f20576f726c64'
    const result = await runCLIWithStdin(
        ['encode', 'multi', '-i', 'hex'],
        input
    )

    t.ok(result.code !== 0, 'command should fail without --type')
    t.ok(result.stderr.includes('--type is required'),
        'error message should mention --type is required')
})

test('encode command - hex to multi format with k256 key type', async t => {
    // Sample hex string representing a secp256k1 public key
    // (33 bytes compressed) 0x02 or 0x03 prefix + 32 bytes x coordinate
    const input = '02' + '1234567890abcdef'.repeat(4)
    const result = await runCLIWithStdin([
        'encode',
        'multi',
        '-i',
        'hex',
        '--type',
        'k256'
    ], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()

    // Multi format output for k256 should start with z (base58btc)
    t.ok(output.startsWith('z'),
        'k256 multikey format should start with z prefix')

    // Decode and verify multicodec prefix
    const decoded = u.fromString(output.slice(1), 'base58btc')
    t.equal(decoded[0], 0xe7,
        'first byte should be 0xe7 (secp256k1 multicodec)')
})

test('encode k256 multikey to hex preserves multicodec prefix', async t => {
    // Generate a k256 key and get its multikey
    const keyResult = await runCLI(['keys', 'k256'])
    t.equal(keyResult.code, 0, 'keys command should exit with code 0')

    const keyOutput = JSON.parse(keyResult.stdout.trim())
    const multikey = keyOutput.publicKey

    // Convert multikey -> hex
    const hexResult = await runCLIWithStdin(
        ['encode', 'hex', '-i', 'multi'],
        multikey
    )
    t.equal(hexResult.code, 0, 'multi to hex conversion should succeed')
    const hexValue = hexResult.stdout.trim()

    // Verify hex includes the multicodec prefix (0xe7)
    t.ok(hexValue.startsWith('e7'),
        'hex output should include secp256k1 multicodec prefix (e7)')

    // Verify length is 68 chars (34 bytes * 2: 1 multicodec + 33 key)
    t.equal(hexValue.length, 68,
        'hex output should be 68 chars (34 bytes: 1 multicodec + 33 key)')
})

test('encode round-trip: k256 multi -> hex -> multi', async t => {
    // Generate a k256 key
    const keyResult = await runCLI(['keys', 'k256'])
    t.equal(keyResult.code, 0, 'keys command should exit with code 0')

    const keyOutput = JSON.parse(keyResult.stdout.trim())
    const originalMulti = keyOutput.publicKey

    // Convert multi -> hex
    const hexResult = await runCLIWithStdin(
        ['encode', 'hex', '-i', 'multi'],
        originalMulti
    )
    t.equal(hexResult.code, 0, 'multi to hex conversion should succeed')
    const hexValue = hexResult.stdout.trim()

    // Verify hex starts with e7 multicodec
    t.ok(hexValue.startsWith('e7'),
        'hex should include secp256k1 multicodec prefix')

    // Convert hex -> multi
    const multiResult = await runCLIWithStdin([
        'encode',
        'multi',
        '-i',
        'hex',
        '--type',
        'k256'
    ], hexValue)
    t.equal(multiResult.code, 0, 'hex to multi conversion should succeed')
    const finalMulti = multiResult.stdout.trim()

    // Should match the original
    t.equal(finalMulti, originalMulti,
        'round-trip conversion should preserve the original k256 multikey')
})

test('encode round-trip: multi -> hex -> multi preserves multikey', async t => {
    // Start with a known multikey (Ed25519)
    const originalMulti = 'z6Mkmy1ak2zS6hPohyNnPwMUDqpC3WE8wTR3Fcz5esUoCFNH'

    // Convert multi -> hex
    const hexResult = await runCLIWithStdin(
        ['encode', 'hex', '-i', 'multi'],
        originalMulti
    )
    t.equal(hexResult.code, 0, 'multi to hex conversion should succeed')
    const hexValue = hexResult.stdout.trim()

    // Verify hex includes the multicodec prefix
    t.ok(hexValue.startsWith('ed01'),
        'hex output should include Ed25519 multicodec prefix')

    // Convert hex -> multi
    const multiResult = await runCLIWithStdin([
        'encode',
        'multi',
        '-i',
        'hex',
        '--type',
        'ed25519'
    ], hexValue)
    t.equal(multiResult.code, 0, 'hex to multi conversion should succeed')
    const finalMulti = multiResult.stdout.trim()

    // Should match the original
    t.equal(finalMulti, originalMulti,
        'round-trip conversion should preserve the original multikey')
})

test('Ed25519 JWK has both public and private key components', async t => {
    const result = await runCLI(['keys', 'ed25519', '-f', 'jwk'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const jwk = JSON.parse(result.stdout.trim())

    t.equal(jwk.kty, 'OKP', 'should have kty OKP')
    t.equal(jwk.crv, 'Ed25519', 'should have crv Ed25519')
    t.ok(jwk.x, 'should have x (public key) component')
    t.ok(jwk.d, 'should have d (private key) component')

    // Verify the components are base64url encoded
    t.ok(/^[A-Za-z0-9_-]+$/.test(jwk.x), 'x should be base64url encoded')
    t.ok(/^[A-Za-z0-9_-]+$/.test(jwk.d), 'd should be base64url encoded')
})

test('RSA JWK contains all required components', async t => {
    const result = await runCLI(['keys', 'rsa', '-f', 'jwk'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const jwk = JSON.parse(result.stdout.trim())

    t.equal(jwk.kty, 'RSA', 'should have kty RSA')
    t.ok(jwk.n, 'should have n (modulus)')
    t.ok(jwk.e, 'should have e (public exponent)')
    t.ok(jwk.d, 'should have d (private exponent)')
    t.ok(jwk.p, 'should have p (first prime)')
    t.ok(jwk.q, 'should have q (second prime)')
})

// Test the `sign` command
test('sign command signs a string with a private key seed', async t => {
    // First generate a keypair to get a private key seed
    const keyResult = await runCLI(['keys', 'ed25519'])
    t.equal(keyResult.code, 0, 'keys command should exit with code 0')

    const keyOutput = JSON.parse(keyResult.stdout.trim())
    const privateKeySeed = keyOutput.privateKey

    // Sign a message
    const message = 'my signed document'
    const result = await runCLI(['sign', message, '-k', privateKeySeed])

    t.equal(result.code, 0, 'sign command should exit with code 0')

    const output = result.stdout.trim()
    t.ok(output.length > 0, 'should output a signature')
    // Ed25519 signatures are 64 bytes,
    // so base64url encoded should be 86 characters (no padding)
    t.ok(/^[A-Za-z0-9_-]+$/.test(output),
        'signature should be base64url encoded')
})

test('sign command requires --key option', async t => {
    const message = 'my signed document'
    const result = await runCLI(['sign', message])

    t.ok(result.code !== 0,
        'should exit with non-zero code when key is missing')
    t.ok(
        (result.stderr.includes('required') || result.stderr.includes('Missing')),
        'should show error about missing key'
    )
})

test('sign command shows help with --help flag', async t => {
    const result = await runCLI(['sign', '--help'])

    t.equal(result.code, 0, 'help command should exit with code 0')
    t.ok(result.stdout.includes('sign'), 'should show command name')
    t.ok(
        result.stdout.includes('key') || result.stdout.includes('-k'),
        'should mention key option'
    )
})

test('sign command produces consistent signatures for same input', async t => {
    // Generate a keypair
    const keyResult = await runCLI(['keys', 'ed25519'])
    t.equal(keyResult.code, 0, 'keys command should exit with code 0')

    const keyOutput = JSON.parse(keyResult.stdout.trim())
    const privateKeySeed = keyOutput.privateKey

    const message = 'consistent message'

    // Sign the same message twice
    const result1 = await runCLI(['sign', message, '-k', privateKeySeed])
    const result2 = await runCLI(['sign', message, '-k', privateKeySeed])

    t.equal(result1.code, 0, 'first sign should succeed')
    t.equal(result2.code, 0, 'second sign should succeed')

    const sig1 = result1.stdout.trim()
    const sig2 = result2.stdout.trim()

    t.equal(sig1, sig2,
        'signatures should be identical for same message and key')
})

test('sign command accepts message from stdin', async t => {
    // Generate a keypair
    const keyResult = await runCLI(['keys', 'ed25519'])
    t.equal(keyResult.code, 0, 'keys command should exit with code 0')

    const keyOutput = JSON.parse(keyResult.stdout.trim())
    const privateKeySeed = keyOutput.privateKey

    // Sign a message from stdin
    const message = 'message from stdin'
    const result = await runCLIWithStdin(
        ['sign', '-k', privateKeySeed],
        message
    )

    t.equal(result.code, 0, 'sign command should exit with code 0')

    const output = result.stdout.trim()
    t.ok(output.length > 0, 'should output a signature')
    t.ok(/^[A-Za-z0-9_-]+$/.test(output),
        'signature should be base64url encoded')
})

test('sign command with stdin produces same signature as positional argument',
    async t => {
        // Generate a keypair
        const keyResult = await runCLI(['keys', 'ed25519'])
        t.equal(keyResult.code, 0, 'keys command should exit with code 0')

        const keyOutput = JSON.parse(keyResult.stdout.trim())
        const privateKeySeed = keyOutput.privateKey

        const message = 'test message'

        // Sign with positional argument
        const result1 = await runCLI(['sign', message, '-k', privateKeySeed])
        t.equal(result1.code, 0, 'positional argument sign should succeed')

        // Sign with stdin
        const result2 = await runCLIWithStdin(
            ['sign', '-k', privateKeySeed],
            message
        )
        t.equal(result2.code, 0, 'stdin sign should succeed')

        const sig1 = result1.stdout.trim()
        const sig2 = result2.stdout.trim()

        t.equal(sig1, sig2, 'signatures should be identical regardless ' +
            'of input method')
    })

test('sign command errors when both message and stdin are missing', async t => {
    // This test would require TTY manipulation which is complex
    // We'll test that the command handles empty stdin
    const keyResult = await runCLI(['keys', 'ed25519'])
    const keyOutput = JSON.parse(keyResult.stdout.trim())
    const privateKeySeed = keyOutput.privateKey

    // Provide empty stdin
    const result = await runCLIWithStdin(['sign', '-k', privateKeySeed], '')

    t.ok(result.code !== 0, 'should fail with empty message')
})

// ------------------------------
// JS API Tests
// ------------------------------

test('JS API: keys() generates Ed25519 keypair by default', async t => {
    const keypair = await keys()

    t.ok(keypair.publicKey, 'should have publicKey property')
    t.ok(keypair.privateKey, 'should have privateKey property')
    t.ok(typeof keypair.publicKey === 'string', 'publicKey should be a string')
    t.ok(typeof keypair.privateKey === 'string', 'privateKey should be a string')
    if (typeof keypair.publicKey === 'string') {
        t.ok(keypair.publicKey.startsWith('z6Mk'),
            'publicKey should be in multikey format')
    }
})

test('JS API: keys() generates X25519 keypair', async t => {
    const keypair = await keys({ keyType: 'x25519' })

    t.ok(keypair.publicKey, 'should have publicKey property')
    t.ok(keypair.privateKey, 'should have privateKey property')
    t.ok(typeof keypair.publicKey === 'string', 'publicKey should be a string')
    t.ok(typeof keypair.privateKey === 'string', 'privateKey should be a string')
})

test('JS API: keys() generates k256 (secp256k1) keypair', async t => {
    const keypair = await keys({ keyType: 'k256' })

    t.ok(keypair.publicKey, 'should have publicKey property')
    t.ok(keypair.privateKey, 'should have privateKey property')
    t.ok(typeof keypair.publicKey === 'string', 'publicKey should be a string')
    t.ok(typeof keypair.privateKey === 'string', 'privateKey should be a string')

    // Verify public key is in multikey format
    if (typeof keypair.publicKey === 'string') {
        t.ok(keypair.publicKey.startsWith('z'),
            'k256 public key should be in multikey format (z prefix)')

        // Decode multikey to verify it's 34 bytes
        // (1 byte multicodec + 33 bytes compressed key)
        const multikey = keypair.publicKey.slice(1) // Remove 'z' prefix
        const decoded = u.fromString(multikey, 'base58btc')
        t.equal(decoded.length, 34,
            'decoded multikey should be 34 bytes ' +
                '(1 multicodec + 33 compressed key)')
        t.equal(decoded[0], 0xe7,
            'first byte should be 0xe7 (secp256k1 multicodec)')
        // Second byte should be 0x02 or 0x03 (compressed key prefix)
        t.ok(decoded[1] === 0x02 || decoded[1] === 0x03,
            'compressed public key should start with 0x02 or 0x03')
    }
})

test('JS API: keys() generates k256 JWK format', async t => {
    const jwk = await keys({
        keyType: 'k256',
        format: 'jwk'
    }) as Record<string, unknown>

    t.equal(jwk.kty, 'EC', 'should have kty EC')
    t.equal(jwk.crv, 'secp256k1', 'should have crv secp256k1')
    t.ok(jwk.d, 'should have d (private key) component')
    t.ok(jwk.x, 'should have x (public key x coordinate) component')
    t.ok(jwk.y, 'should have y (public key y coordinate) component')
})

test('JS API: keys() generates JWK format', async t => {
    const jwk = await keys({ format: 'jwk' }) as Record<string, unknown>

    t.equal(jwk.kty, 'OKP', 'should have kty OKP')
    t.equal(jwk.crv, 'Ed25519', 'should have crv Ed25519')
    t.ok(jwk.d, 'should have d (private key) component')
    t.ok(jwk.x, 'should have x (public key) component')
})

test('JS API: sign() signs a message', async t => {
    const keypair = await keys()
    if (typeof keypair.privateKey === 'string') {
        const message = 'test message'
        const signature = await sign(message, { key: keypair.privateKey })

        t.ok(signature, 'should return a signature')
        t.ok(typeof signature === 'string', 'signature should be a string')
        t.ok(/^[A-Za-z0-9_-]+$/.test(signature),
            'signature should be base64url encoded')
    }
})

test('JS API: sign() produces consistent signatures', async t => {
    const keypair = await keys()
    if (typeof keypair.privateKey === 'string') {
        const message = 'consistent message'

        const sig1 = await sign(message, { key: keypair.privateKey })
        const sig2 = await sign(message, { key: keypair.privateKey })

        t.equal(sig1, sig2,
            'signatures should be identical for same message and key')
    }
})

test('JS API: sign() signs with RSA keys', async t => {
    const keypair = await keys({ keyType: 'rsa' })
    if (typeof keypair.privateKeyPem === 'string') {
        const message = 'test message for RSA'
        const signature = await sign(message, { key: keypair.privateKeyPem })

        t.ok(signature, 'should return a signature')
        t.ok(typeof signature === 'string', 'signature should be a string')
        t.ok(/^[A-Za-z0-9_-]+$/.test(signature),
            'signature should be base64url encoded')
        // RSA-PSS signatures are 256 bytes (2048-bit key), base64url encoded
        t.ok(signature.length > 300,
            'RSA signature should be longer than Ed25519')
    }
})

test('keys() generates RSA encryption keypair with use=exchange', async t => {
    const keypair = await keys({
        keyType: 'rsa',
        use: 'exchange',
        format: 'jwk'
    }) as any

    // Should return RSA JWK
    t.equal(keypair.kty, 'RSA', 'should be RSA JWK')
    t.ok(keypair.d, 'should have d (private exponent)')
    t.ok(keypair.n, 'should have n (modulus)')
})

test('JS API: encode() converts UTF-8 to base64', async t => {
    const input = 'Hello World'
    const encoded = await encode(input, {
        inputFormat: 'utf8',
        outputFormat: 'base64'
    })

    t.ok(encoded, 'should return encoded string')
    // Note: base64 encoding without padding
    t.equal(encoded, 'SGVsbG8gV29ybGQ', 'should correctly encode to base64')
})

test('JS API: encode() converts base64 to hex', async t => {
    const encoded = await encode('SGVsbG8gV29ybGQ=', {
        inputFormat: 'base64',
        outputFormat: 'hex'
    })

    t.equal(encoded, '48656c6c6f20576f726c64',
        'should correctly convert to hex')
})

test('JS API: decode() decodes base64 to UTF-8', async t => {
    const decoded = await decode('SGVsbG8gV29ybGQ=', {
        inputFormat: 'base64'
    })

    t.equal(decoded, 'Hello World', 'should correctly decode to UTF-8')
})

test('JS API: decode() decodes hex to UTF-8', async t => {
    const decoded = await decode('48656c6c6f20576f726c64', {
        inputFormat: 'hex'
    })

    t.equal(decoded, 'Hello World', 'should correctly decode hex to UTF-8')
})

/**
 * Helper function to run the CLI command and capture output
 */
function runCLI (args:string[]):Promise<{
    stdout:string
    stderr:string
    code:number | null
}> {
    return new Promise((resolve) => {
        const child = spawn('node', [CLI_PATH, ...args])
        let stdout = ''
        let stderr = ''

        child.stdout.on('data', (data) => {
            stdout += data.toString()
        })

        child.stderr.on('data', (data) => {
            stderr += data.toString()
        })

        child.on('close', (code) => {
            resolve({ stdout, stderr, code })
        })
    })
}

/**
 * Helper function to run the CLI command with stdin input
 */
function runCLIWithStdin (args:string[], input:string):Promise<{
    stdout:string
    stderr:string
    code:number | null
}> {
    return new Promise((resolve) => {
        const child = spawn('node', [CLI_PATH, ...args])
        let stdout = ''
        let stderr = ''

        child.stdout.on('data', (data) => {
            stdout += data.toString()
        })

        child.stderr.on('data', (data) => {
            stderr += data.toString()
        })

        child.on('close', (code) => {
            resolve({ stdout, stderr, code })
        })

        // Write input to stdin
        child.stdin.write(input)
        child.stdin.end()
    })
}
