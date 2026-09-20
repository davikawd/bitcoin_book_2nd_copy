import { createCipheriv, randomBytes, scryptSync } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { gzipSync } from 'node:zlib'

const KEY_ENV_NAME = 'FILE_ENCRYPTION_KEY'
const VERSION = 4

export async function encryptFile(inputPath, outputPath, keyText, textMode = false) {
  if (!keyText) throw new Error(`${KEY_ENV_NAME} must not be empty`)
  if (resolve(inputPath) === resolve(outputPath)) {
    throw new Error('output path must be different from input path')
  }

  const salt = randomBytes(16)
  const iv = randomBytes(12)
  const header = Buffer.concat([Buffer.from([VERSION]), salt, iv])
  const key = scryptSync(keyText, salt, 32)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  cipher.setAAD(header)
  const ciphertext = Buffer.concat([cipher.update(await readFile(inputPath)), cipher.final()])

  const encrypted = Buffer.concat([header, ciphertext, cipher.getAuthTag()])
  const encryptRepresentation = textMode
    ? Buffer.from(encrypted.toString('base64'), 'ascii')
    : encrypted
  const compressed = gzipSync(
    Buffer.concat([Buffer.from([textMode ? 1 : 0]), encryptRepresentation]),
    { level: 9 },
  )
  await writeFile(
    outputPath,
    textMode ? `${compressed.toString('base64')}\n` : compressed,
    { flag: 'wx' },
  )
}

export async function main(
  args = process.argv.slice(2),
  keyText = process.env[KEY_ENV_NAME] ?? '',
  log = console.log,
) {
  const textMode = args.includes('--text')
  const [inputPath, requestedOutputPath] = args.filter(arg => arg !== '--text')
  if (!inputPath) {
    throw new Error(
      `usage: ${KEY_ENV_NAME}=<your key string> node scripts/encrypt-file.mjs [--text] <input> [output]`,
    )
  }

  const outputPath = requestedOutputPath
    ?? `${inputPath}.encrypted${textMode ? '.txt' : ''}`
  await encryptFile(inputPath, outputPath, keyText, textMode)
  log(`Encrypted ${inputPath} -> ${outputPath}`)
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
