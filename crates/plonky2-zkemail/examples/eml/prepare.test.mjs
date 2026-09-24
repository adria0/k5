import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { prepareEmail, relaxedBody, relaxedHeader, signedHeaders } from './prepare.mjs';

const raw = readFileSync(new URL('../fixtures/test.eml', import.meta.url));
const key = JSON.parse(readFileSync(new URL('../fixtures/icloud-dkim.json', import.meta.url), 'utf8'));

test('real email verifies with LF or SMTP CRLF endings', () => {
  const prepared = prepareEmail(raw, key);
  assert.equal(prepared.domain, 'icloud.com');
  assert.deepEqual(prepareEmail(Buffer.from(raw.toString().replace(/\r?\n/g, '\r\n')), key), prepared);
});

test('relaxed canonicalization handles folding, tabs, trailing lines, and empty bodies', () => {
  assert.equal(relaxedHeader({ name: 'SUBJECT', value: ' \tHello\r\n\t world \t' }), 'subject:Hello world');
  assert.equal(relaxedBody(' \tHello \t\r\nworld\t \r\n\r\n').toString(), ' Hello\r\nworld\r\n');
  assert.equal(relaxedBody('\t \r\n\r\n').length, 0);
  const variant = Buffer.from(raw.toString().replace('Subject: Hello', 'SUBJECT:\r\n\tHello \t'));
  assert.deepEqual(prepareEmail(variant, key), prepareEmail(raw, key));
});

test('repeated signed fields are selected bottom-up and absent fields add nothing', () => {
  assert.equal(signedHeaders([
    { name: 'X-Tag', value: 'top' }, { name: 'x-tag', value: 'bottom' },
  ], ['x-tag', 'x-tag', 'x-tag']), 'x-tag:bottom\r\nx-tag:top\r\n');
});

test('tampering with the signed body or header is rejected before proving', () => {
  assert.throws(() => prepareEmail(Buffer.from(raw.toString().replace('How are you?', 'How are we?')), key), /body hash mismatch/);
  assert.throws(() => prepareEmail(Buffer.from(raw.toString().replace('Subject: Hello', 'Subject: Changed')), key), /RSA signature mismatch/);
});

test('wrong domain, selector, and public key are rejected', () => {
  assert.throws(() => prepareEmail(raw, { ...key, domain: 'example.com' }), /domain\/selector/);
  assert.throws(() => prepareEmail(raw, { ...key, selector: 'other' }), /domain\/selector/);
  const der = Buffer.from(key.record.split('p=')[1], 'base64');
  const jwk = createPublicKey({ key: der, format: 'der', type: 'spki' }).export({ format: 'jwk' });
  const modulus = Buffer.from(jwk.n, 'base64url');
  modulus[10] ^= 1;
  jwk.n = modulus.toString('base64url');
  const wrongKey = createPublicKey({ key: jwk, format: 'jwk' }).export({ format: 'der', type: 'spki' });
  assert.throws(() => prepareEmail(raw, { ...key, record: `v=DKIM1; k=rsa; p=${wrongKey.toString('base64')}` }), /RSA signature mismatch/);
});

test('an i= identity outside the signing domain is rejected', () => {
  const altered = Buffer.from(raw.toString().replace('d=icloud.com;', 'd=icloud.com; i=user@example.com;'));
  assert.throws(() => prepareEmail(altered, key), /identity domain/);
});

test('unsupported modes and ambiguous tags fail explicitly', () => {
  for (const [before, after, error] of [
    ['c=relaxed/relaxed', 'c=simple/relaxed', /relaxed\/relaxed/],
    ['a=rsa-sha256', 'a=rsa-sha1', /rsa-sha256/],
    ['v=1;', 'v=1; l=0;', /Partial-body/],
    ['v=1;', 'v=1; v=1;', /duplicate/],
  ]) {
    assert.throws(() => prepareEmail(Buffer.from(raw.toString().replace(before, after)), key), error);
  }
  assert.throws(() => prepareEmail(Buffer.concat([Buffer.from('DKIM-Signature: v=1;\n'), raw]), key), /exactly one/);
});
