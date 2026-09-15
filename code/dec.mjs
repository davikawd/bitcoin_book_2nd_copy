import { createDecipheriv, scryptSync } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const KEY_ENV_NAME = 'FILE_ENCRYPTION_KEY'
const ENCRYPTED_SUFFIX = '.encrypted.json'

export async function decryptFile(inputPath, outputPath, keyText) {
  if (!keyText) {
    throw new Error(`${KEY_ENV_NAME} must not be empty`)
  }

  if (resolve(inputPath) === resolve(outputPath)) {
    throw new Error('output path must be different from input path')
  }

  const envelope = JSON.parse(await readFile(inputPath, 'utf8'))

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

  await writeFile(outputPath, Buffer.from(payload.toString('utf8'), 'base64'), { flag: 'wx' })
}

function defaultOutputPath(inputPath) {
  if (inputPath.endsWith(ENCRYPTED_SUFFIX)) {
    return `${inputPath.slice(0, -ENCRYPTED_SUFFIX.length)}.decrypted`
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
