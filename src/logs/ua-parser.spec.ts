import { deviceFromUa } from './ua-parser';

describe('deviceFromUa', () => {
  it.each([
    [
      'iPhone',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
    ],
    [
      'iPad',
      'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
    ],
  ])('identifies %s as iOS despite its Mac OS compatibility token', (_, ua) => {
    expect(deviceFromUa(ua)).toBe('Safari on iOS');
  });

  it.each([
    [
      'Safari on macOS',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    ],
    [
      'Chrome on Android',
      'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36',
    ],
    [
      'Edge on Windows',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0',
    ],
    [
      'Firefox on Linux',
      'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
    ],
  ])('preserves %s detection', (expected, ua) => {
    expect(deviceFromUa(ua)).toBe(expected);
  });

  it.each([undefined, null, ''])(
    'returns null for absent user agent %p',
    (ua) => {
      expect(deviceFromUa(ua)).toBeNull();
    },
  );

  it('keeps the fallback for unrecognized user agents', () => {
    expect(deviceFromUa('custom-client/1.0')).toBe('Browser on Unknown');
  });
});
