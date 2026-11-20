/**
 * frontend/crypto.js - Browser Cryptography & Shifting Codes Ratchet
 * Mirrors user_gateway/src/crypto.rs and ratchet.rs exactly using WebCrypto.
 */

// Hex helpers
export function hexToBytes(hex) {
  if (typeof hex !== 'string') return new Uint8Array(0);
  const clean = hex.trim();
  if (clean.length % 2 !== 0) throw new Error('Invalid hex string length');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let hex = '';
  for (let i = 0; i < arr.length; i++) {
    hex += arr[i].toString(16).padStart(2, '0');
  }
  return hex;
}

// SHA-256 helper
export async function sha256Bytes(dataBytes) {
  const hash = await crypto.subtle.digest('SHA-256', dataBytes);
  return new Uint8Array(hash);
}

export async function sha256Hex(data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = await sha256Bytes(bytes);
  return bytesToHex(hash);
}

// Config hash hex (mirrors config_hash_hex in crypto.rs)
export async function configHashHex(config) {
  return await sha256Hex(config);
}

// HMAC-SHA256 primitive via WebCrypto
export async function hmacSha256(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, dataBytes);
  return new Uint8Array(sig);
}

// HKDF-Extract (RFC 5869)
// If salt is null or empty, defaults to 32 zero bytes (HashLen for SHA-256)
export async function hkdfExtract(salt, ikm) {
  const effectiveSalt = (!salt || salt.length === 0) ? new Uint8Array(32) : salt;
  return await hmacSha256(effectiveSalt, ikm);
}

// HKDF-Expand (RFC 5869) for length <= 32 bytes (1 block: T(1) = HMAC(PRK, info || 0x01))
export async function hkdfExpand(prk, infoBytes, length) {
  const input = new Uint8Array(infoBytes.length + 1);
  input.set(infoBytes, 0);
  input[infoBytes.length] = 1;
  const t1 = await hmacSha256(prk, input);
  return t1.slice(0, length);
}

// Derive session seed (mirrors derive_session_seed in crypto.rs)
// seed = HKDF-SHA256(ikm = shared_secret, salt = nonce, info = "lot-gateway/session-seed/v1" + device_id, length = 32)
export async function deriveSessionSeed(sharedSecretBytes, nonceBytes, deviceId) {
  const prk = await hkdfExtract(nonceBytes, sharedSecretBytes);
  const prefix = new TextEncoder().encode('lot-gateway/session-seed/v1');
  const devIdBytes = new TextEncoder().encode(deviceId);
  const info = new Uint8Array(prefix.length + devIdBytes.length);
  info.set(prefix, 0);
  info.set(devIdBytes, prefix.length);
  return await hkdfExpand(prk, info, 32);
}

// Derive next key in chain (mirrors next_key in ratchet.rs)
// key_n = HKDF-SHA256(ikm = key_{n-1}, salt = None, info = "lot-gateway/chain/v1", length = 32)
export async function nextKey(keyBytes) {
  const prk = await hkdfExtract(null, keyBytes);
  const info = new TextEncoder().encode('lot-gateway/chain/v1');
  return await hkdfExpand(prk, info, 32);
}

// Derive code from key and counter (mirrors code_from_key in ratchet.rs)
// code_n = HKDF-SHA256(ikm = key_n, salt = None, info = "lot-gateway/code/v1" + counter (8 bytes big-endian), length = 16)
export async function codeFromKey(keyBytes, counterBigInt) {
  const prk = await hkdfExtract(null, keyBytes);
  const prefix = new TextEncoder().encode('lot-gateway/code/v1');
  const info = new Uint8Array(prefix.length + 8);
  info.set(prefix, 0);
  const view = new DataView(info.buffer, info.byteOffset + prefix.length, 8);
  view.setBigUint64(0, BigInt(counterBigInt), false); // big-endian
  const codeBytes = await hkdfExpand(prk, info, 16);
  return bytesToHex(codeBytes);
}

// Client code calculation for counter (mirrors client_code in ratchet.rs)
export async function clientCode(seedBytes, counter) {
  const c = BigInt(counter);
  if (c <= 0n || c > 1000000n) {
    throw new Error('counter must be between 1 and 1000000');
  }
  let key = seedBytes;
  for (let i = 0n; i < c; i++) {
    key = await nextKey(key);
  }
  return await codeFromKey(key, c);
}

// ASN.1 prefix for Ed25519 PrivateKeyInfo per RFC 8410:
// 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 (16 bytes) + 32-byte seed
const ED25519_PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420');

// Check if Ed25519 is supported by the browser WebCrypto implementation
export async function isEd25519Supported() {
  try {
    if (!crypto?.subtle?.importKey) return false;
    const dummyKey = new Uint8Array(32);
    // Try raw first
    try {
      await crypto.subtle.importKey('raw', dummyKey, { name: 'Ed25519' }, false, ['sign']);
      return true;
    } catch (_) {
      // Try standard W3C pkcs8
      const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
      pkcs8.set(ED25519_PKCS8_PREFIX, 0);
      pkcs8.set(dummyKey, ED25519_PKCS8_PREFIX.length);
      await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
      return true;
    }
  } catch (err) {
    return false;
  }
}

// Sign raw nonce bytes using Ed25519 private key seed (32 bytes)
export async function signNonce(signingKeyHex, nonceHex) {
  const seedBytes = hexToBytes(signingKeyHex);
  const nonceBytes = hexToBytes(nonceHex);

  if (!crypto?.subtle) {
    throw new Error('WebCrypto is not supported by this browser. Please use Chrome 113+, Edge 113+, Safari 17+, or Firefox 129+.');
  }

  let key;
  // 1. Try importing as raw
  try {
    key = await crypto.subtle.importKey(
      'raw',
      seedBytes,
      { name: 'Ed25519' },
      false,
      ['sign']
    );
  } catch (_) {
    // 2. Try importing as W3C standard PKCS#8 (RFC 8410)
    try {
      const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + seedBytes.length);
      pkcs8.set(ED25519_PKCS8_PREFIX, 0);
      pkcs8.set(seedBytes, ED25519_PKCS8_PREFIX.length);
      key = await crypto.subtle.importKey(
        'pkcs8',
        pkcs8,
        { name: 'Ed25519' },
        false,
        ['sign']
      );
    } catch (err) {
      throw new Error('WebCrypto Ed25519 is not supported by this browser. Please use Chrome 113+, Edge 113+, Safari 17+, or Firefox 129+.');
    }
  }

  const sig = await crypto.subtle.sign('Ed25519', key, nonceBytes);
  return bytesToHex(new Uint8Array(sig));
}
