import { test, expect } from '@playwright/test';

test.describe('Devin API E2E Tests', () => {
  test.describe('API Connectivity', () => {
    test('should verify Devin API endpoint is reachable', async ({ request }) => {
      const response = await request.head('https://api.devin.ai/v1/sessions');
      expect([401, 403, 405]).toContain(response.status());
    });
  });

  test.describe('API Response Validation', () => {
    test('should return proper error for unauthenticated requests', async ({ request }) => {
      const response = await request.post('https://api.devin.ai/v1/sessions', {
        data: { prompt: 'test' },
        headers: {
          'Content-Type': 'application/json',
        },
      });
      expect([401, 403]).toContain(response.status());
    });

    test('should return proper error for invalid API key', async ({ request }) => {
      const response = await request.post('https://api.devin.ai/v1/sessions', {
        data: { prompt: 'test' },
        headers: {
          'Authorization': 'Bearer invalid_key',
          'Content-Type': 'application/json',
        },
      });
      expect([401, 403]).toContain(response.status());
    });
  });

  test.describe('Request Format Validation', () => {
    test('should handle malformed JSON gracefully', async ({ request }) => {
      const response = await request.post('https://api.devin.ai/v1/sessions', {
        headers: {
          'Content-Type': 'application/json',
        },
        data: 'invalid json',
      });
      expect([400, 401, 403, 422]).toContain(response.status());
    });
  });
});

test.describe('Log File Validation', () => {
  test('should verify log files exist in expected location', async () => {
    const fs = await import('fs');
    const path = await import('path');

    const logsDir = path.join(process.cwd(), 'logs');
    expect(fs.existsSync(logsDir)).toBe(true);
  });

  test('should verify log files are valid JSON', async () => {
    const fs = await import('fs');
    const path = await import('path');

    const logsDir = path.join(process.cwd(), 'logs');
    const files = fs.readdirSync(logsDir).filter((f: string) => f.endsWith('.json'));

    for (const file of files) {
      const content = fs.readFileSync(path.join(logsDir, file), 'utf-8');
      expect(() => JSON.parse(content)).not.toThrow();
    }
  });

  test('should verify analysis directory exists', async () => {
    const fs = await import('fs');
    const path = await import('path');

    const analysisDir = path.join(process.cwd(), 'analysis');
    expect(fs.existsSync(analysisDir)).toBe(true);
  });
});
