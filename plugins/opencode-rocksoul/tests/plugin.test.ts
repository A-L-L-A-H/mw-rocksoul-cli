import { describe, expect, test } from 'bun:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createRocksoulOpenCodePlugin,
  injectRidBearerHeaders,
  isProtectedGovernanceOrSecretPath,
  RocksoulPolicyError,
  type CoreRiskEvaluateRequest,
} from '../src/index.ts';

interface CapturedCoreCall {
  readonly authHeader: string | null;
  readonly agentHeader: string | null;
  readonly body: CoreRiskEvaluateRequest;
}

describe('opencode-rocksoul plugin', () => {
  test('allows R0/R1 calls approved by mw-rocksoul-core and injects mw-rid Bearer header', async () => {
    const captured: CapturedCoreCall[] = [];
    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        const url = new URL(req.url);
        if (req.method === 'POST' && url.pathname === '/v1/risk/evaluate') {
          const body = (await req.json()) as CoreRiskEvaluateRequest;
          captured.push({
            authHeader: req.headers.get('authorization'),
            agentHeader: req.headers.get('x-mw-agent'),
            body,
          });
          return Response.json({
            allowed: true,
            decision: 'allow',
            effectiveRiskTier: body.requestedTier,
            dataClassification: body.dataClassification,
            targetZone: body.targetZone,
            reasonCodes: [],
            messages: [],
          });
        }
        return new Response('not found', { status: 404 });
      },
    });

    try {
      const plugin = createRocksoulOpenCodePlugin({
        coreBaseUrl: `http://127.0.0.1:${server.port}`,
        dataClassification: 'local_only',
        getBearerToken: () => 'rid-jwt-live-token',
      });

      await plugin['tool.execute.before'](
        { tool: 'read', callID: 'c1' },
        { args: { filePath: 'src/app.ts' } }
      );
      await plugin['tool.execute.before'](
        { tool: 'edit', callID: 'c2' },
        { args: { filePath: 'src/app.ts', target: 'a', replacement: 'b' } }
      );

      expect(captured).toHaveLength(2);
      expect(captured[0]?.authHeader).toBe('Bearer rid-jwt-live-token');
      expect(captured[0]?.agentHeader).toBe('opencode-rocksoul');
      expect(captured[0]?.body.requestedTier).toBe('R0');
      expect(captured[0]?.body.targetPaths).toEqual(['src/app.ts']);
      expect(captured[1]?.body.requestedTier).toBe('R1');
      expect(captured[1]?.body.action).toBe('edit_file');

      const chatHeaders: Record<string, string> = {};
      await plugin['chat.headers']({ provider: 'rocksoul' }, { headers: chatHeaders });
      expect(chatHeaders.Authorization).toBe('Bearer rid-jwt-live-token');
      expect(chatHeaders['X-MW-Agent']).toBe('opencode-rocksoul');
      expect(chatHeaders['X-Rocksoul-Data-Classification']).toBe('local_only');
    } finally {
      server.stop(true);
    }
  });

  test('blocks protected governance paths (.githooks/*, .env, CODEOWNERS) and destructive shell at R4 before calling core', async () => {
    let coreCallCount = 0;
    const server = Bun.serve({
      port: 0,
      fetch() {
        coreCallCount += 1;
        return Response.json({
          allowed: true,
          decision: 'allow',
          effectiveRiskTier: 'R0',
          dataClassification: 'local_only',
          targetZone: 'local',
          reasonCodes: [],
          messages: [],
        });
      },
    });

    try {
      const plugin = createRocksoulOpenCodePlugin({
        coreBaseUrl: `http://127.0.0.1:${server.port}`,
      });

      const blockedPaths = [
        '.githooks/pre-commit',
        '.env',
        'apps/api/.env.production',
        '.github/CODEOWNERS',
        '.agents/rules/autonomous-git-release-lock.md',
        '../outside/secret.txt',
      ];
      for (const blockedPath of blockedPaths) {
        expect(isProtectedGovernanceOrSecretPath(blockedPath)).toBe(true);
        await expect(
          plugin['tool.execute.before']({ tool: 'edit' }, { args: { filePath: blockedPath } })
        ).rejects.toThrow(RocksoulPolicyError);
      }

      // .env.example is explicitly allowed to reach core policy evaluation.
      expect(isProtectedGovernanceOrSecretPath('.env.example')).toBe(false);

      // Destructive shell commands blocked locally at R4.
      await expect(
        plugin['tool.execute.before']({ tool: 'bash' }, { args: { command: 'rm -rf ./dist' } })
      ).rejects.toThrow(RocksoulPolicyError);
      await expect(
        plugin['tool.execute.before']({ tool: 'bash' }, { args: { command: 'git reset --hard HEAD~1' } })
      ).rejects.toThrow(RocksoulPolicyError);
      await expect(
        plugin['tool.execute.before']({ tool: 'bash' }, { args: { command: 'cat .env' } })
      ).rejects.toThrow(RocksoulPolicyError);

      expect(coreCallCount).toBe(0);
    } finally {
      server.stop(true);
    }
  });

  test('enforces core deny / require_human_approval and fails closed when core is unreachable', async () => {
    const server = Bun.serve({
      port: 0,
      fetch() {
        return Response.json({
          allowed: false,
          decision: 'require_human_approval',
          effectiveRiskTier: 'R3',
          dataClassification: 'local_only',
          targetZone: 'cloud',
          reasonCodes: ['HUMAN_APPROVAL_REQUIRED'],
          messages: ['Risk tier R3 requires human approval token.'],
        });
      },
    });

    try {
      const plugin = createRocksoulOpenCodePlugin({
        coreBaseUrl: `http://127.0.0.1:${server.port}`,
      });

      let caught: unknown;
      try {
        await plugin['tool.execute.before'](
          { tool: 'webfetch' },
          { args: { url: 'https://example.com' } }
        );
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(RocksoulPolicyError);
      const policyErr = caught as RocksoulPolicyError;
      expect(policyErr.riskTier).toBe('R3');
      expect(policyErr.decision).toBe('require_human_approval');
      expect(policyErr.reasonCodes).toContain('HUMAN_APPROVAL_REQUIRED');
    } finally {
      server.stop(true);
    }

    // Fail-closed when mw-rocksoul-core is completely unreachable.
    const offlinePlugin = createRocksoulOpenCodePlugin({
      coreBaseUrl: 'http://127.0.0.1:1',
      timeoutMs: 500,
    });
    await expect(
      offlinePlugin['tool.execute.before']({ tool: 'read' }, { args: { filePath: 'README.md' } })
    ).rejects.toThrow(/Fail-closed/u);
  });

  test('loads valid mw-rid Bearer token from token.json and skips expired tokens', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'rocksoul-plugin-'));
    try {
      const validPath = join(tempDir, 'valid-token.json');
      await writeFile(
        validPath,
        JSON.stringify({
          access_token: 'rid-file-token-xyz',
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
        }),
        'utf8'
      );

      const headers1: Record<string, string> = {};
      await injectRidBearerHeaders(headers1, { tokenFilePath: validPath });
      expect(headers1.Authorization).toBe('Bearer rid-file-token-xyz');

      const expiredPath = join(tempDir, 'expired-token.json');
      await writeFile(
        expiredPath,
        JSON.stringify({
          access_token: 'rid-expired-token',
          expires_at: new Date(Date.now() - 60_000).toISOString(),
        }),
        'utf8'
      );

      const headers2: Record<string, string> = {};
      await injectRidBearerHeaders(headers2, { tokenFilePath: expiredPath });
      expect(headers2.Authorization).toBeUndefined();
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  test('plugin source maintains zero @moonwitness/orm-* imports and zero explicit any types', async () => {
    const src = await readFile(join(import.meta.dir, '../src/index.ts'), 'utf8');
    expect(src).not.toContain('@moonwitness/orm-');
    expect(src).not.toMatch(/:\s*any\b|\bas\s+any\b|<any>/u);
  });
});
