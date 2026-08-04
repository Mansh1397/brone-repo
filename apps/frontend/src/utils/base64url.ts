export function base64urlToBase64(base64url: string): string {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return base64;
}

export function base64ToBase64url(base64: string): string {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function safeBufferFromBase64Url(base64urlStr: string): Buffer {
  return Buffer.from(base64urlToBase64(base64urlStr), 'base64');
}

export function safeBufferToBase64Url(buf: Buffer): string {
  return base64ToBase64url(buf.toString('base64'));
}
