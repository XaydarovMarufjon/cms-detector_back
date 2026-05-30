import type { Request } from 'express';

export function extractIp(req: Request): string | undefined {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  if (Array.isArray(forwarded) && forwarded[0]) {
    return forwarded[0].split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || undefined;
}

export function extractUa(req: Request): string | undefined {
  const ua = req.headers['user-agent'];
  return Array.isArray(ua) ? ua[0] : ua;
}

export function deviceFromUa(userAgent?: string | null): string | null {
  if (!userAgent) return null;
  const ua = userAgent.toLowerCase();
  const os =
    ua.includes('windows') ? 'Windows' :
    ua.includes('mac os') || ua.includes('macintosh') ? 'macOS' :
    ua.includes('iphone') || ua.includes('ipad') ? 'iOS' :
    ua.includes('android') ? 'Android' :
    ua.includes('linux') ? 'Linux' :
    'Unknown';
  const browser =
    ua.includes('edg/') ? 'Edge' :
    ua.includes('chrome/') ? 'Chrome' :
    ua.includes('safari/') && !ua.includes('chrome/') ? 'Safari' :
    ua.includes('firefox/') ? 'Firefox' :
    'Browser';
  return `${browser} on ${os}`;
}
