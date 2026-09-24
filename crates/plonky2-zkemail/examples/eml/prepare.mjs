// Deliberately bounded example adapter: one rsa-sha256, relaxed/relaxed signature.
// Canonicalization follows RFC 6376 sections 3.4, 3.7, and 5.4.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function requireCondition(ok, message) {
  if (!ok) throw new Error(message);
}

const trimWsp = (value) => value.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');

// Reject duplicate tags instead of silently choosing one interpretation.
function tags(value) {
  const result = new Map();
  for (const part of value.split(';')) {
    if (!trimWsp(part)) continue;
    const match = /^([a-z][a-z0-9_]*)[ \t]*=([\s\S]*)$/.exec(trimWsp(part));
    requireCondition(match && !result.has(match[1]), 'Malformed or duplicate DKIM tag');
    result.set(match[1], trimWsp(match[2]));
  }
  return result;
}

// Node's Base64 decoder is permissive; round-trip to reject malformed encodings.
function decodeBase64(value, label) {
  requireCondition(typeof value === 'string', `Missing ${label}`);
  const text = value.replace(/[ \t\r\n]/g, '');
  const decoded = Buffer.from(text, 'base64');
  requireCondition(text.length > 0 && decoded.toString('base64') === text, `Invalid ${label}`);
  return decoded;
}

// Preserve octets through Latin-1 strings; only ASCII whitespace is transformed.
export function relaxedHeader(header) {
  const value = header.value.replace(/\r\n/g, '').replace(/[ \t]+/g, ' ')
    .replace(/^ | $/g, '');
  return `${header.name.toLowerCase()}:${value}`;
}

export function relaxedBody(body) {
  const lines = body.split('\r\n').map((line) => line.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
  while (lines.length && lines.at(-1) === '') lines.pop();
  return Buffer.from(lines.length ? `${lines.join('\r\n')}\r\n` : '', 'latin1');
}

// Apply h= order, choosing repeated header fields from the bottom upwards.
export function signedHeaders(headers, names) {
  const used = new Set();
  const selected = [];
  for (const name of names) {
    for (let i = headers.length - 1; i >= 0; i--) {
      if (headers[i].name.toLowerCase() === name && !used.has(i)) {
        used.add(i);
        selected.push(`${relaxedHeader(headers[i])}\r\n`);
        break;
      }
    }
    // An oversigned field which does not exist contributes no bytes (RFC 6376).
  }
  return selected.join('');
}

// Prepare canonical bytes only after checking the body hash and RSA signature.
export function prepareEmail(raw, trustedKey) {
  const original = raw.toString('latin1');
  requireCondition(!/\r(?!\n)/.test(original), 'Bare CR line endings are unsupported');
  // The repository fixture is LF-only. Restore SMTP CRLF before canonicalizing.
  const message = original.replace(/\r?\n/g, '\r\n');
  const boundary = message.indexOf('\r\n\r\n');
  requireCondition(boundary >= 0, 'Missing header/body separator');
  const headers = [];
  for (const line of message.slice(0, boundary).split('\r\n')) {
    if (/^[ \t]/.test(line)) {
      requireCondition(headers.length > 0, 'Orphan header continuation');
      headers.at(-1).value += `\r\n${line}`;
    } else {
      const match = /^([\x21-\x39\x3b-\x7e]+):([\s\S]*)$/.exec(line);
      requireCondition(match, 'Malformed email header');
      headers.push({ name: match[1], value: match[2] });
    }
  }
  const signatures = headers.filter((h) => h.name.toLowerCase() === 'dkim-signature');
  requireCondition(signatures.length === 1, 'Example requires exactly one DKIM signature');
  const dkim = signatures[0];
  const signatureTags = tags(dkim.value);
  requireCondition(signatureTags.get('v') === '1', 'Example requires DKIM v=1');
  requireCondition(signatureTags.get('a') === 'rsa-sha256', 'Example requires rsa-sha256');
  requireCondition(signatureTags.get('c') === 'relaxed/relaxed', 'Example requires relaxed/relaxed');
  requireCondition(!signatureTags.has('l'), 'Partial-body l= signatures are unsupported');
  requireCondition(signatureTags.get('d') === trustedKey.domain && signatureTags.get('s') === trustedKey.selector,
    'Signing domain/selector does not match the trusted key record');
  if (signatureTags.has('i')) {
    const identity = signatureTags.get('i');
    const at = identity.lastIndexOf('@');
    const identityDomain = identity.slice(at + 1).toLowerCase();
    const signingDomain = signatureTags.get('d').toLowerCase();
    requireCondition(at >= 0 && identity.indexOf('@') === at && identityDomain.length > 0
      && (identityDomain === signingDomain || identityDomain.endsWith(`.${signingDomain}`)),
    'DKIM identity domain is outside the signing domain');
  }

  const body = relaxedBody(message.slice(boundary + 4));
  const bodyHash = createHash('sha256').update(body).digest();
  requireCondition(bodyHash.equals(decodeBase64(signatureTags.get('bh'), 'body hash')),
    'DKIM body hash mismatch');
  const names = (signatureTags.get('h') ?? '').toLowerCase().split(':').map(trimWsp);
  requireCondition(names.includes('from') && headers.some((h) => h.name.toLowerCase() === 'from'),
    'A signed From header is required');
  requireCondition(names.every((name) => /^[\x21-\x39\x3b-\x7e]+$/.test(name) && name !== 'dkim-signature'),
    'Unsupported signed-header list');
  const blankSignature = dkim.value.split(';').map((part) => {
    const match = /^[ \t\r\n]*b[ \t]*=/.exec(part);
    return match ? match[0] : part;
  }).join(';');
  const signedDkim = relaxedHeader({ name: dkim.name, value: blankSignature });
  const prefix = signedHeaders(headers, names);
  // The DKIM-Signature field itself has no trailing CRLF in the signed input.
  const header = Buffer.from(prefix + signedDkim, 'latin1');
  const match = /; bh=([A-Za-z0-9+/=]{44});/.exec(signedDkim);
  requireCondition(match && match[1] === bodyHash.toString('base64'),
    'Body hash formatting is unsupported by the circuit regex');
  const bodyHashIndex = Buffer.byteLength(prefix, 'latin1') + match.index + 5;

  const keyTags = tags(trustedKey.record);
  requireCondition(keyTags.get('v') === 'DKIM1' && keyTags.get('k') === 'rsa', 'Expected an RSA DKIM public key');
  const der = decodeBase64(keyTags.get('p'), 'public key');
  const publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' });
  requireCondition(publicKey.asymmetricKeyType === 'rsa', 'Expected an RSA public key');
  const jwk = publicKey.export({ format: 'jwk' });
  const modulus = Buffer.from(jwk.n, 'base64url');
  requireCondition(Buffer.from(jwk.e, 'base64url').toString('hex') === '010001', 'RSA exponent must be 65537');
  requireCondition(modulus.length === 256, 'Example expects a 2048-bit RSA key');
  const signature = decodeBase64(signatureTags.get('b'), 'signature');
  requireCondition(verify('RSA-SHA256', header, publicKey, signature), 'DKIM RSA signature mismatch');

  return {
    domain: trustedKey.domain,
    selector: trustedKey.selector,
    header: [...header],
    body: [...body],
    body_hash_index: bodyHashIndex,
    modulus_hex: modulus.toString('hex'),
    signature_hex: signature.toString('hex'),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    requireCondition(process.argv.length === 4, 'Usage: node prepare.mjs EMAIL.eml TRUSTED_KEY.json');
    const result = prepareEmail(readFileSync(process.argv[2]), JSON.parse(readFileSync(process.argv[3], 'utf8')));
    process.stdout.write(JSON.stringify(result));
  } catch (error) {
    console.error(`Email preparation failed: ${error.message}`);
    process.exitCode = 1;
  }
}
