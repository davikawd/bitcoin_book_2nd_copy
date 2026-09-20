import { createDecipheriv, scryptSync } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { gunzipSync } from 'node:zlib'

const KEY_ENV_NAME = 'FILE_ENCRYPTION_KEY'
const VERSION = 4
const PREVIOUS_VERSION = 2
const HEADER_SIZE = 29
const AUTH_TAG_SIZE = 16

function decodeTextContainer(encrypted) {
  const text = encrypted.toString('utf8').trim()
  if (!text || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    throw new Error('invalid or unsupported encrypted file')
  }
  return Buffer.from(text, 'base64')
}

function decryptCurrent(encrypted, keyText) {
  const version = encrypted[0]
  if (
    encrypted.length < HEADER_SIZE + AUTH_TAG_SIZE
    || (version !== VERSION && version !== PREVIOUS_VERSION)
  ) {
    throw new Error('invalid or unsupported encrypted file')
  }

  const header = encrypted.subarray(0, HEADER_SIZE)
  const salt = encrypted.subarray(1, 17)
  const iv = encrypted.subarray(17, HEADER_SIZE)
  const ciphertext = encrypted.subarray(HEADER_SIZE, -AUTH_TAG_SIZE)
  const key = scryptSync(keyText, salt, 32)
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAAD(header)
  decipher.setAuthTag(encrypted.subarray(-AUTH_TAG_SIZE))
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

// ponytail: only retained so files created by the previous script remain recoverable.
function decryptLegacy(encrypted, keyText) {
  const envelope = JSON.parse(encrypted.toString('utf8'))
  if (
    envelope.version !== 1
    || envelope.algorithm !== 'aes-256-gcm'
    || envelope.keyDerivation !== 'scrypt'
    || envelope.encoding !== 'base64'
    || !Number.isSafeInteger(envelope.rounds)
    || envelope.rounds < 1
    || !Array.isArray(envelope.layers)
    || envelope.layers.length !== envelope.rounds
    || typeof envelope.salt !== 'string'
    || typeof envelope.ciphertext !== 'string'
  ) {
    throw new Error('invalid or unsupported encrypted file')
  }

  const key = scryptSync(keyText, Buffer.from(envelope.salt, 'base64'), 32)
  let payload = Buffer.from(envelope.ciphertext, 'base64')
  for (const layer of envelope.layers.toReversed()) {
    if (typeof layer?.iv !== 'string' || typeof layer?.authTag !== 'string') {
      throw new Error('invalid encryption layer')
    }
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(layer.iv, 'base64'))
    decipher.setAuthTag(Buffer.from(layer.authTag, 'base64'))
    payload = Buffer.concat([decipher.update(payload), decipher.final()])
  }
  return Buffer.from(payload.toString('utf8'), 'base64')
}

export async function decryptFile(inputPath, outputPath, keyText) {
  if (!keyText) throw new Error(`${KEY_ENV_NAME} must not be empty`)
  if (resolve(inputPath) === resolve(outputPath)) {
    throw new Error('output path must be different from input path')
  }

  const encrypted = await readFile(inputPath)
  let content
  try {
    if (encrypted[0] === 0x7b) {
      content = decryptLegacy(encrypted, keyText)
    }
    else {
      let container = encrypted
      const recognized = container[0] === 0x1f && container[1] === 0x8b
        || container[0] === VERSION
        || container[0] === PREVIOUS_VERSION
      if (!recognized) container = decodeTextContainer(container)

      if (container[0] === 0x1f && container[1] === 0x8b) {
        const decompressed = gunzipSync(container, {
          maxOutputLength: Math.max(1024 * 1024, container.length * 16),
        })
        const mode = decompressed[0]
        if (mode !== 0 && mode !== 1) {
          throw new Error('invalid or unsupported encrypted file')
        }
        container = mode === 1
          ? decodeTextContainer(decompressed.subarray(1))
          : decompressed.subarray(1)
      }
      content = decryptCurrent(container, keyText)
    }
  }
  catch (error) {
    if (error instanceof Error && error.message === 'invalid or unsupported encrypted file') {
      throw error
    }
    throw new Error('decryption failed: wrong key or damaged file')
  }
  await writeFile(outputPath, content, { flag: 'wx' })
}

function defaultOutputPath(inputPath) {
  for (const suffix of [
    '.encrypted.txt',
    '.encrypted',
    '.encrypted-text.gz',
    '.encrypted.gz',
    '.encrypted.json',
  ]) {
    if (inputPath.endsWith(suffix)) {
      return `${inputPath.slice(0, -suffix.length)}.decrypted`
    }
  }
  return `${inputPath}.decrypted`
}

export async function main(
  args = process.argv.slice(2),
  keyText = process.env[KEY_ENV_NAME] ?? '',
  log = console.log,
) {
  const [inputPath, requestedOutputPath] = args
  if (!inputPath) {
    throw new Error(
      `usage: ${KEY_ENV_NAME}=<your key string> node scripts/decrypt-file.mjs <input> [output]`,
    )
  }

  const outputPath = requestedOutputPath ?? defaultOutputPath(inputPath)
  await decryptFile(inputPath, outputPath, keyText)
  log(`Decrypted ${inputPath} -> ${outputPath}`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    await main()
  }
  catch (error) {
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
  }
}
