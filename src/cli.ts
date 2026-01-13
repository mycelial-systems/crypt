#!/usr/bin/env node
import 'dotenv/config'
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import * as u from 'uint8arrays'
import chalk from 'chalk'
import { writeFileSync } from 'node:fs'
import {
    keys,
    encode,
    decode,
    sign,
    derivePublicKey,
    formatOutput
} from './index.js'

// Only run CLI if this file is being executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    await yargs(hideBin(process.argv))
        .command(
            'public <privateKey>',
            'Get the public key or keypair given a private key',
            (yargs) => {
                return yargs
                    .positional('private', {
                        describe: 'The private key (hex encoded by default)',
                        demandOption: true
                    })
                    .option('type', {
                        alias: 't',
                        describe: 'Type of the given private key',
                        demandOption: true,
                        type: 'string',
                        choices: ['ed25519', 'x25519', 'rsa', 'k256']
                    })
                    .option('input', {
                        alias: 'i',
                        describe: 'Private key format',
                        type: 'string',
                        choices: ['hex', 'base64', 'base64url'],
                        default: 'hex'
                    })
                    .option('format', {
                        alias: 'f',
                        describe: 'Output format for the public key. "json" ' +
                            'means publicKey will be encoded as a DID format ' +
                            'string (did:key:...)',
                        type: 'string',
                        default: 'json',
                        choices: ['json', 'hex', 'base64url', 'base64', 'did']
                    })
            },
            async argv => {
                await publicCommand({
                    privateKey: argv.privateKey as string,
                    keyType: argv.type as 'ed25519'|'x25519'|'rsa'|'k256',
                    format: argv.format as 'json'|'hex'|'base64url'|'base64'|'did',
                    input: argv.input as 'hex'|'base64'|'base64url',
                })
            }
        )
        .command(
            'keys [type]',
            'Create a new keypair',
            (yargs) => {
                return yargs
                    .positional('type', {
                        describe: 'The key type to use for the new key',
                        type: 'string',
                        choices: ['ed25519', 'x25519', 'rsa', 'k256'],
                        default: 'ed25519'
                    })
                    .option('format', {
                        alias: 'f',
                        describe: 'Output format',
                        type: 'string',
                        choices: ['raw', 'jwk', 'did'],
                        default: 'raw'
                    })
                    .option('output', {
                        alias: 'o',
                        describe: 'Output file for private key ' +
                            '(required for RSA unless using -f jwk; ' +
                            'optional for Ed25519/X25519)',
                        type: 'string'
                    })
                    .option('use', {
                        alias: 'u',
                        describe: 'Key usage for RSA keys (sign or exchange)',
                        type: 'string',
                        choices: ['sign', 'exchange'],
                        default: 'sign'
                    })
            },
            async (argv) => {
                await keysCommand({
                    keyType: argv.type as 'ed25519' | 'x25519' | 'rsa' | 'k256',
                    format: argv.format as 'raw' | 'jwk' | 'did',
                    output: argv.output as string | undefined,
                    use: argv.use as 'sign' | 'exchange'
                })
            }
        )
        .command(
            'encode [output-format]',
            'Encode a string from one format to another',
            (yargs) => {
                return yargs
                    .positional('output-format', {
                        describe: 'The desired output format',
                        type: 'string',
                        choices: ['base64', 'hex', 'base64url', 'base58btc',
                            'utf8', 'ascii', 'multi'],
                        default: 'base64url'
                    })
                    .option('input-format', {
                        alias: 'i',
                        describe: 'The format of the input string',
                        type: 'string',
                        choices: ['base64', 'hex', 'base64url', 'base58btc',
                            'utf8', 'ascii', 'multi'],
                        default: 'utf8'
                    })
                    .option('type', {
                        alias: 't',
                        describe: 'Key type (required when ' +
                            'output-format is multi)',
                        type: 'string',
                        choices: ['ed25519', 'rsa', 'k256']
                    })
                    .check((argv) => {
                        if (argv['output-format'] === 'multi' && !argv.type) {
                            throw new Error('--type is required when ' +
                                'output-format is "multi"')
                        }
                        return true
                    })
            },
            async (argv) => {
                // Read from stdin
                const input = (await readStdin()).trim()

                const result = await encodeCommand(
                    input,
                    argv['input-format'] as u.SupportedEncodings | 'multi',
                    argv['output-format'] as u.SupportedEncodings | 'multi',
                    argv.type as 'ed25519' | 'rsa' | 'k256' | undefined
                )
                console.log(result)
            }
        )
        .command(
            'decode [input-format]',
            'Decode a string to UTF-8',
            (yargs) => {
                return yargs
                    .positional('input-format', {
                        describe: 'The format of the input string',
                        type: 'string',
                        choices: ['base64', 'base64pad', 'hex', 'base64url',
                            'base58btc', 'ascii', 'multi'],
                        default: 'base64'
                    })
            },
            async (argv) => {
                // Read from stdin
                const input = (await readStdin()).trim()

                const result = await decodeCommand(
                    input,
                    argv['input-format'] as u.SupportedEncodings
                )
                console.log(result)
            }
        )
        .command(
            'sign [message]',
            'Sign a string with a private key',
            (yargs) => {
                return yargs
                    .positional('message', {
                        describe: 'The message to sign (or read ' +
                            'from stdin if omitted)',
                        type: 'string'
                    })
                    .option('key', {
                        alias: 'k',
                        describe: 'Private key seed (base64url encoded)',
                        type: 'string',
                        demandOption: true
                    })
            },
            async (argv) => {
                // If message is not provided as argument, read from stdin
                let message: string
                if (argv.message) {
                    message = argv.message
                } else {
                    message = (await readStdin()).trim()
                }

                const result = await signCommand(
                    message,
                    argv.key as string
                )
                console.log(result)
            }
        )
        .demandCommand(1, 'You must provide a command')
        .help()
        .alias('help', 'h')
        .parse()
}

/**
 * CLI command handler for keys command.
 */
async function keysCommand (args: {
    keyType: 'ed25519' | 'x25519' | 'rsa' | 'k256',
    format: 'did' | 'raw' | 'jwk',
    output?: string,  // the file path to write output to
    use?: 'sign' | 'exchange'
} = { keyType: 'ed25519', format: 'raw' }) {
    const publicFormat = args.format || 'raw'

    // For RSA, require output file unless format is 'jwk'
    if (args.keyType === 'rsa' && publicFormat !== 'jwk' && !args.output) {
        console.error(chalk.red('Error: RSA keys require an output file. ' +
            'Use -o or --output to specify the private key file, ' +
            'or use -f jwk for JWK output.'))
        process.exit(1)
    }

    try {
        const result = await keys(args)

        if (args.output) {
            // Write private key to file
            if ('privateKeyPem' in result) {
                // RSA PEM format
                writeFileSync(
                    args.output,
                    result.privateKeyPem as string,
                    'utf8'
                )
            } else if (publicFormat === 'jwk') {
                // JWK format - result is the JWK itself
                writeFileSync(
                    args.output,
                    JSON.stringify(result, null, 2),
                    'utf8'
                )
                // For JWK, also output the public key portion to stdout
                console.log(JSON.stringify({ publicKey: result }, null, 2))
                return
            } else if (
                'privateKey' in result &&
                typeof result.privateKey === 'string'
            ) {
                // Raw format (seed)
                writeFileSync(args.output, result.privateKey, 'utf8')
            }

            // Output only public key to stdout (for raw/PEM formats)
            if ('publicKey' in result) {
                console.log(
                    JSON.stringify({ publicKey: result.publicKey }, null, 2)
                )
            }
        } else {
            // Output to stdout
            if (publicFormat === 'jwk') {
                // For JWK format, result is the JWK directly
                console.log(JSON.stringify(result, null, 2))
            } else {
                // For raw format, result has publicKey and privateKey
                console.log(JSON.stringify(result, null, 2))
            }
        }
    } catch (err) {
        console.error(chalk.red('Error generating keypair:'), err)
        process.exit(1)
    }
}

/**
 * CLI command handler for public command.
 */
async function publicCommand (args: {
    privateKey: string,
    keyType: 'ed25519' | 'x25519' | 'rsa' | 'k256',
    format: 'json' | 'hex' | 'base64url' | 'base64' | 'did',
    input: 'hex' | 'base64' | 'base64url'
}) {
    try {
        const result = await derivePublicKey(args.privateKey, {
            keyType: args.keyType,
            inputFormat: args.input,
        })

        const { format, privateKey, keyType } = args
        if (format === 'json') {
            // print JSON with keys
            console.log(JSON.stringify({
                publicKey: await formatOutput(result, 'did', keyType, true),
                privateKey,
                keyType
            }, null, 2))
        } else if (format === 'did') {
            // return just the did encoded public key
            console.log(await formatOutput(result, 'did', keyType, true))
        } else {
            // not JSON format, log just the public key
            console.log(u.toString(result, format))
        }
    } catch (err) {
        console.error(chalk.red('Error deriving public key:'), err)
        process.exit(1)
    }
}

/**
 * CLI command handler for encode command.
 */
async function encodeCommand (
    input: string,
    inputFormat: u.SupportedEncodings | 'multi',
    outputFormat: u.SupportedEncodings | 'multi',
    keyType?: 'ed25519' | 'rsa' | 'k256'
): Promise<string> {
    try {
        return await encode(input, {
            inputFormat,
            outputFormat,
            keyType
        })
    } catch (err) {
        console.error(chalk.red('Error encoding:'), err)
        process.exit(1)
    }
}

/**
 * CLI command handler for decode command.
 */
async function decodeCommand (
    input: string,
    inputFormat: u.SupportedEncodings
): Promise<string> {
    try {
        return await decode(input, { inputFormat })
    } catch (err) {
        console.error(chalk.red('Error decoding:'), err)
        process.exit(1)
    }
}

/**
 * CLI command handler for sign command.
 */
async function signCommand (
    message: string,
    privateKeySeed: string
): Promise<string> {
    try {
        return await sign(message, { key: privateKeySeed })
    } catch (err) {
        console.error(chalk.red('Error signing message:'), err)
        process.exit(1)
    }
}

/**
 * Read all data from stdin.
 */
async function readStdin (): Promise<string> {
    return new Promise((resolve, reject) => {
        const chunks: Buffer[] = []
        process.stdin.on('data', (chunk) => {
            chunks.push(chunk)
        })
        process.stdin.on('end', () => {
            resolve(Buffer.concat(chunks).toString())
        })
        process.stdin.on('error', reject)
    })
}
