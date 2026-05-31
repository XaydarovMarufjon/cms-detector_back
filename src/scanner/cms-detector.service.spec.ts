jest.mock('socks-proxy-agent', () => ({
  SocksProxyAgent: class MockSocksProxyAgent {},
}));

jest.mock('https-proxy-agent', () => ({
  HttpsProxyAgent: class MockHttpsProxyAgent {},
}));

import { CmsDetectorService } from './cms-detector.service';
import { CMS_DETECTOR_FIXTURES } from './cms-detector.fixtures';

describe('CmsDetectorService fixture detection', () => {
  const service = new CmsDetectorService();

  for (const fixture of CMS_DETECTOR_FIXTURES) {
    it(fixture.name, () => {
      const result = service.detectFromHtml(
        fixture.url,
        fixture.html,
        fixture.headers ?? {},
      );

      expect(result.cms).toBe(fixture.expectedCms);
      expect(result.category).toBe(fixture.expectedCategory);
      expect(result.confidence).toBeGreaterThanOrEqual(fixture.minConfidence);
      if (result.cms) {
        expect(result.rawSignals).toHaveProperty('_evidence');
      }
      if (result.version) {
        expect(result.rawSignals).toHaveProperty('_version_source');
      }
    });
  }
});
