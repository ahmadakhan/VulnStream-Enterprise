import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
  createHash,
} from 'node:crypto';
const scrypt = (password: string, salt: string, length: number) =>
  new Promise<Buffer>((resolve, reject) =>
    scryptCallback(
      password,
      salt,
      length,
      { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 },
      (error, result) => (error ? reject(error) : resolve(result)),
    ),
  );
export const tokenHash = (value: string) => createHash('sha256').update(value).digest('hex');
export const randomToken = () => randomBytes(32).toString('base64url');
export async function passwordHash(password: string) {
  const salt = randomBytes(16).toString('hex');
  const result = (await scrypt(password, salt, 64)) as Buffer;
  return `scrypt131072$${salt}$${result.toString('hex')}`;
}
export async function checkPassword(password: string, stored: string) {
  const [algorithm, salt, expected] = stored.split('$');
  if (algorithm !== 'scrypt131072' || !salt || !/^[0-9a-f]{128}$/.test(expected || '')) return false;
  const result = (await scrypt(password, salt, 64)) as Buffer;
  return timingSafeEqual(result, Buffer.from(expected, 'hex'));
}
export function encrypt(value: string, key: string, context: string): string {
  if (!value) return '';
  const iv = randomBytes(12),
    cipher = createCipheriv('aes-256-gcm', Buffer.from(key, 'base64'), iv);
  cipher.setAAD(Buffer.from(context));
  const payload = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [
    'v1',
    iv.toString('base64'),
    cipher.getAuthTag().toString('base64'),
    payload.toString('base64'),
  ].join('.');
}
export function decrypt(value: string, key: string, context: string): string {
  if (!value) return '';
  const parts = value.split('.');
  const [version, iv, tag, body] = parts;
  if (
    parts.length !== 4 ||
    [iv, tag, body].some((v) => !v || Buffer.from(v, 'base64').toString('base64') !== v) ||
    Buffer.from(iv, 'base64').length !== 12 ||
    Buffer.from(tag, 'base64').length !== 16
  )
    throw new Error('Invalid encrypted secret encoding');
  if (version !== 'v1' || !iv || !tag || !body) throw new Error('Invalid encrypted secret');
  const cipher = createDecipheriv('aes-256-gcm', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
  cipher.setAAD(Buffer.from(context));
  cipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([cipher.update(Buffer.from(body, 'base64')), cipher.final()]).toString('utf8');
}
export function secureEqual(a: string, b: string) {
  return timingSafeEqual(Buffer.from(tokenHash(a)), Buffer.from(tokenHash(b)));
}
