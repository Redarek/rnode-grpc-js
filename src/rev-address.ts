/**
 * RChain REV‑address utilities — generation, parsing and validation.
 *
 * Design overview
 * ----------------
 * Keys and addresses form a one‑way chain:
 *
 *   mnemonic → private key → public key → Ethereum address → REV address
 *
 *  * **Mnemonic**   — BIP‑39 (English wordlist, 128‑bit entropy → 12 words).
 *  * **Private key**— secp256k1, 32‑byte hex string.
 *  * **Public key** — uncompressed, 65‑byte (0x04 + X + Y) hex string.
 *  * **ETH address**— last 20 bytes of the Keccak‑256 hash of the public key.
 *  * **REV address**— ETH address + network prefix + Blake2b checksum, then Base58‑encoded.
 *
 * Functions exported by this module:
 *
 *   • {@link newRevAddress}           — generate a brand‑new wallet.
 *   • {@link revAddressFromMnemonic}  — restore wallet from a mnemonic.
 *   • {@link parseRevAddress}         — detect what the caller passed (priv/pub/eth/rev) and convert.
 *   • {@link verifyRevAddr}           — checksum validation for a REV address.
 *   • Low‑level helpers: {@link getAddrFromEth}, {@link getAddrFromPublicKey}, {@link getAddrFromPrivateKey}.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * All cryptography matches the reference implementation in RChain RNode:
 * https://github.com/rchain/rchain/tree/dev/rholang/src/main/scala/coop/rchain/rholang/interpreter/util
 */

import { keccak256 } from 'js-sha3'
import { blake2bHex } from 'blakejs'
import { ec } from 'elliptic'
import { decodeBase16, encodeBase58, encodeBase16, decodeBase58safe } from './codecs'
import * as bip39 from 'bip39'
import HDKey from 'hdkey'

/**
 * Wallet descriptor returned by most helpers.
 *
 * Only `revAddr` is guaranteed to be present; other fields are added when they are
 * available / derivable from the source you passed in.
 */
export interface RevAddress {
  /** Base58‑encoded address usable on‑chain. */
  revAddr: string
  /** 40‑char Ethereum address (hex, **without** 0x‑prefix). */
  ethAddr?: string
  /** 130‑char uncompressed public key (hex, **without** 0x‑prefix). */
  pubKey?: string
  /** 64‑char private key (hex, **without** 0x‑prefix). */
  privKey?: string
  /** Original BIP‑39 mnemonic if the wallet was generated/restored from it. */
  mnemonic?: string
}

const secp256k1 = new ec('secp256k1')

const prefix = {
  /** 3‑byte coin identifier: 0x000000 */
  coinId : '000000',
  /** single‑byte version: 0x00 */
  version: '00',
} as const

/**
 * Convert an **Ethereum address** to a **REV address**.
 *
 * @param ethAddrRaw 40‑char hex string (with or without `0x`).
 * @returns Base58‑encoded REV address or `undefined` on bad input.
 */
export function getAddrFromEth(ethAddrRaw: string): string | undefined {
  const ethAddr = ethAddrRaw.replace(/^0x/, '')
  if (!ethAddr || ethAddr.length !== 40) return

  // keccak256(ethAddr)
  const ethHash = keccak256(decodeBase16(ethAddr))

  // payload = prefix + hash, checksum = blake2b256(payload) first 4 bytes
  const payload      = `${prefix.coinId}${prefix.version}${ethHash}`
  const checksum     = blake2bHex(decodeBase16(payload), void 666, 32).slice(0, 8)

  return encodeBase58(`${payload}${checksum}`)
}

/**
 * Derive both REV and ETH addresses from **public key**.
 *
 * @param publicKeyRaw 130‑char uncompressed key (hex, with or without `0x`).
 * @returns All derived addresses or `undefined` on invalid input.
 */
export function getAddrFromPublicKey(publicKeyRaw: string): RevAddress | undefined {
  const publicKey = publicKeyRaw.replace(/^0x/, '')
  if (!publicKey || publicKey.length !== 130) return void 666

  // Drop 1‑byte prefix (0x04) and hash the remaining 64 bytes
  const pkHash  = keccak256(decodeBase16(publicKey).slice(1))
  const ethAddr = pkHash.slice(-40) // last 20 bytes

  const revAddr = getAddrFromEth(ethAddr)
  return revAddr ? { revAddr, ethAddr } : void 666
}

/**
 * Derive public / ETH / REV addresses from **private key**.
 *
 * @param privateKeyRaw 64‑char hex string (with or without `0x`).
 * @returns All derived keys or `undefined` on invalid input.
 */
export function getAddrFromPrivateKey(privateKeyRaw: string): RevAddress | undefined {
  const privateKey = privateKeyRaw.replace(/^0x/, '')
  if (!privateKey || privateKey.length !== 64) return

  const key    = secp256k1.keyFromPrivate(privateKey)
  const pubKey = key.getPublic('hex')
  const addr   = getAddrFromPublicKey(pubKey)

  return addr ? { pubKey, ...addr } : void 666
}

/**
 * Validate a **REV address** (checksum & length only — no on‑chain lookup).
 *
 * @returns `true` if address is syntactically correct.
 */
export function verifyRevAddr(revAddr: string): boolean {
  const revBytes = decodeBase58safe(revAddr)
  if (!revBytes) return false

  const revHex      = encodeBase16(revBytes)
  const payload     = revHex.slice(0, -8)
  const checksum    = revHex.slice(-8)
  const checksumRef = blake2bHex(decodeBase16(payload), void 666, 32).slice(0, 8)

  return checksum === checksumRef
}

/**
 * Create a brand‑new wallet: fresh mnemonic → all keys / addresses.
 *
 * @remarks **Never share the mnemonic or private key — they give full control over the funds.**
 */
export function newRevAddress(): RevAddress {
  const mnemonic = bip39.generateMnemonic()
  const privKey  = privKeyFromMnemonic(mnemonic)
  const addr     = getAddrFromPrivateKey(privKey) as RevAddress

  return { mnemonic, privKey, ...addr }
}

/**
 * Restore a wallet from an existing BIP‑39 mnemonic phrase.
 *
 * @throws Error if the mnemonic fails `bip39.validateMnemonic()`.
 */
export function revAddressFromMnemonic(mnemonic: string): RevAddress {
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error('Invalid BIP-39 mnemonic')
  }

  const privKey = privKeyFromMnemonic(mnemonic)
  const addr    = getAddrFromPrivateKey(privKey) as RevAddress

  return { mnemonic, privKey, ...addr }
}

/**
 * Try to interpret an arbitrary string as one of the supported inputs
 * (private key → public key → ETH → REV) and convert it to a full
 * {@link RevAddress}. Returns `undefined` when the string matches none.
 */
export function parseRevAddress(text: string): RevAddress | undefined {
  const val = text.replace(/^0x/, '').trim()

  const fromPriv = getAddrFromPrivateKey(val)
  const fromPub  = getAddrFromPublicKey(val)
  const fromEth  = getAddrFromEth(val)
  const isRev    = verifyRevAddr(val)

  if (isRev)              return { revAddr: text }
  else if (fromPriv)      return { privKey: val, ...fromPriv }
  else if (fromPub)       return { pubKey:  val, ...fromPub }
  else if (fromEth)       return { ethAddr: val, revAddr: fromEth }
  else                    return void 666
}

/**
 * Derive a secp256k1 private key from a mnemonic using the first
 * account / first address on the standard Ethereum HD path
 * `m/44'/60'/0'/0/0`.
 */
function privKeyFromMnemonic(mnemonic: string): string {
  const seed  = bip39.mnemonicToSeedSync(mnemonic)          // 64‑byte Buffer
  const hd    = HDKey.fromMasterSeed(seed)                  // BIP‑32 root node
  const child = hd.derive("m/44'/60'/0'/0/0")              // first account / address

  if (!child.privateKey) {
    throw new Error('Unable to derive private key (HD node neutered?)')
  }
  return child.privateKey.toString('hex')
}
