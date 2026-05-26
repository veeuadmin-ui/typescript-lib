import argon2 from 'argon2';
import type { SessionData } from './types';

// ================== //
// Password Utilities //
// ================== //

/**
 * Takes a password and returns its digest.
 * Uses a random salt by default.
 * @param password the password to be hashed
 * @returns
 */
export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password);
}

/**
 * Takes a password and a password's digest and checks if they correspond.
 * @param password the password to check
 * @param hash the expected hash
 * @returns
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return argon2.verify(hash, password);
}

// ================= //
// Session Utilities //
// ================= //

/**
 * Generate a cryptographically secure random session ID
 * @returns
 */
function generateSessionId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Create an HMAC signature for a session token
 * @param data
 * @param secret
 * @returns
 */
async function signToken(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify an HMAC signature
 * @param data
 * @param signature
 * @param secret
 * @returns
 */
async function verifySignature(data: string, signature: string, secret: string): Promise<boolean> {
  const expectedSignature = await signToken(data, secret);
  // Constant-time comparison
  if (signature.length !== expectedSignature.length) return false;
  let result = 0;
  for (let i = 0; i < signature.length; i++) {
    result |= signature.charCodeAt(i) ^ expectedSignature.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Create a new session and return the session token.
 * @param sessionPrefix
 * @param sessionDuration
 * @param secret
 * @param storeSessionCb
 * @returns
 */
export async function createSession(
  sessionPrefix: string,
  sessionDuration: number,
  secret: string,
  storeSessionCb: Function
): Promise<string> {
  const sessionId = generateSessionId();
  const expiresAt = Date.now() + sessionDuration;

  // Store session in KV with TTL
  // await kv.put(
  //   `${sessionPrefix}${sessionId}`,
  //   JSON.stringify({ createdAt: Date.now() }),
  //   { expirationTtl: Math.floor(sessionDuration / 1000) }
  // );
  await storeSessionCb(sessionPrefix, sessionId, sessionDuration);

  // Create signed token: sessionId.expiresAt.signature
  const data = `${sessionId}.${expiresAt}`;
  const signature = await signToken(data, secret);

  return `${data}.${signature}`;
}

/**
 * Verify a session token, and return session data if valid.
 * @param token
 * @param kv
 * @param secret
 * @returns
 */
export async function verifySession(
  session_prefix: string,
  token: string,
  secret: string,
  invalidationCb: Function
): Promise<SessionData | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [sessionId, expiresAtStr, signature] = parts;
  const data = `${sessionId}.${expiresAtStr}`;

  // Verify signature
  const isValid = await verifySignature(data, signature, secret);
  if (!isValid) return null;

  // Check expiration
  const expiresAt = parseInt(expiresAtStr, 10);
  if (isNaN(expiresAt) || Date.now() > expiresAt) return null;

  // Check if session exists in KV (not revoked)
  const sessionData = await invalidationCb(`${session_prefix}::${sessionId}`)
  if (!sessionData) return null;

  return { sessionId, expiresAt };
}

// TODO: Invalidate a session (logout)

// ================ //
// Cookie Utilities //
// ================ //

/**
 * Create a Set-Cookie header value for the session.
 * @param sessionCookieName
 * @param sessionDuration
 * @param token
 * @param secure
 * @returns
 */
export function createSessionCookie(sessionCookieName: string, sessionDuration: number, token: string, secure: boolean = true): string {
  const maxAge = Math.floor(sessionDuration / 1000);
  const parts = [
    `${sessionCookieName}=${token}`,
    `Max-Age=${maxAge}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (secure) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

/**
 * Create a Set-Cookie header to clear the session cookie.
 * @param sessionCookieName
 * @returns
 */
export function clearSessionCookie(sessionCookieName: string): string {
  return `${sessionCookieName}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`;
}

/**
 * Extract session token from cookie header.
 * @param sessionCookieName
 * @param cookieHeader
 * @returns
 */
export function getSessionFromCookie(sessionCookieName: string, cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(';').map((c) => c.trim());
  for (const cookie of cookies) {
    const [name, ...valueParts] = cookie.split('=');
    if (name === sessionCookieName) {
      return valueParts.join('=') || null;
    }
  }
  return null;
}
