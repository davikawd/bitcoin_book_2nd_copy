import { createCipheriv, randomBytes, scryptSync } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const KEY_ENV_NAME = 'FILE_ENCRYPTION_KEY'

export async function encryptFile(inputPath, outputPath, rounds, keyText) {
  if (!Number.isSafeInteger(rounds) || rounds < 1) {
    throw new Error('rounds must be a positive integer')
  }

  if (!keyText) {
    throw new Error(`${KEY_ENV_NAME} must not be empty`)
  }

  if (resolve(inputPath) === resolve(outputPath)) {
    throw new Error('output path must be different from input path')
  }

  const salt = randomBytes(16)
  const key = scryptSync(keyText, salt, 32)
  const base64 = (await readFile(inputPath)).toString('base64')
  let payload = Buffer.from(base64, 'utf8')
  const layers = []

  for (let round = 0; round < rounds; round++) {
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    payload = Buffer.concat([cipher.update(payload), cipher.final()])
    layers.push({
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
    })
  }

  const envelope = {
    version: 1,
    algorithm: 'aes-256-gcm',
    keyDerivation: 'scrypt',
    salt: salt.toString('base64'),
    encoding: 'base64',
    rounds,
    layers,
    ciphertext: payload.toString('base64'),
  }

  await writeFile(outputPath, `${JSON.stringify(envelope, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
  })
}

export async function main(
  args = process.argv.slice(2),
  keyText = process.env[KEY_ENV_NAME] ?? '',
  log = console.log,
) {
  const [inputPath, roundsText, requestedOutputPath] = args

  if (!inputPath || !roundsText) {
    throw new Error(
      `usage: ${KEY_ENV_NAME}=<any non-empty string> node scripts/encrypt-file.mjs <input> <rounds> [output]`,
    )
  }

  const outputPath = requestedOutputPath ?? `${inputPath}.encrypted.json`
  const rounds = Number(roundsText)
  await encryptFile(inputPath, outputPath, rounds, keyText)
  log(`Encrypted ${inputPath} ${rounds} time(s) -> ${outputPath}`)
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
