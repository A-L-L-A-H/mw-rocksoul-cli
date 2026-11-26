import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

export type RiskTier = 'R0' | 'R1' | 'R2' | 'R3' | 'R4';
export type DataClassification = 'local_only' | 'cloud_eligible';
export type TargetZone = 'local' | 'cloud';

export interface CoreRiskEvaluateRequest {
  readonly principalId: string;
  readonly action: string;
  readonly capability: string;
  readonly requestedTier: RiskTier;
  readonly dataClassification: DataClassification;
  readonly targetZone: TargetZone;
  readonly targetPaths?: readonly string[];
  readonly readOnlyMode?: boolean;
}

export interface CoreRiskEvaluateDecision {
  readonly allowed: boolean;
  readonly decision: 'allow' | 'require_human_approval' | 'deny';
  readonly effectiveRiskTier: RiskTier;
  readonly dataClassification: DataClassification;
  readonly targetZone: TargetZone;
  readonly reasonCodes: readonly string[];
  readonly messages: readonly string[];
  readonly requiresIndependentVerification?: boolean;
  readonly requiresHumanApproval?: boolean;
  readonly evaluatedAt?: string;
  readonly decisionSha256?: string;
}

export interface ToolExecuteBeforeInput {
  readonly tool: string;
  readonly sessionID?: string;
  readonly callID?: string;
}

export interface ToolExecuteBeforeOutput {
  args: Record<string, unknown>;
}

export interface ChatHeadersInput {
  readonly provider?: string;
  readonly model?: string;
  readonly sessionID?: string;
}

export interface ChatHeadersOutput {
  headers: Record<string, string>;
}

export interface RocksoulOpenCodeHooks {
  readonly 'tool.execute.before': (
    input: ToolExecuteBeforeInput,
    output: ToolExecuteBeforeOutput
  ) => Promise<void>;
  readonly 'chat.headers': (
    input: ChatHeadersInput,
    output: ChatHeadersOutput
  ) => Promise<void>;
}

export interface RocksoulPluginOptions {
  readonly coreBaseUrl?: string;
  readonly principalId?: string;
  readonly dataClassification?: DataClassification;
  readonly readOnlyMode?: boolean;
  readonly tokenFilePath?: string;
  readonly agentHeader?: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
  readonly getBearerToken?: () => Promise<string | null> | string | null;
}

export class RocksoulPolicyError extends Error {
  readonly riskTier: RiskTier;
  readonly decision: string;
  readonly reasonCodes: readonly string[];

  constructor(
    message: string,
    riskTier: RiskTier,
    decision: string,
    reasonCodes: readonly string[]
  ) {
    super(message);
    this.name = 'RocksoulPolicyError';
    this.riskTier = riskTier;
    this.decision = decision;
    this.reasonCodes = reasonCodes;
  }
}

export const DEFAULT_CORE_BASE_URL = 'http://127.0.0.1:4520';
const DEFAULT_PRINCIPAL_ID = 'opencode-rocksoul-agent';
const DEFAULT_AGENT_HEADER = 'opencode-rocksoul';
const DEFAULT_TIMEOUT_MS = 5_000;

const PROTECTED_EXACT_PATHS = new Set<string>([
  '.github/codeowners',
  '.agents/rules/autonomous-git-release-lock.md',
  '.github/workflows/promote.yml',
  '.github/workflows/sync-main-to-dev.yml',
  '.github/workflows/promotion-policy.yml',
  '.github/workflows/release-orchestrate.yml',
  '.github/workflows/release-prepare.yml',
  '.github/workflows/release.yml',
  'scripts/setup-git-hooks.mjs',
  'scripts/sync-main-to-dev.mjs',
  'scripts/release-orchestrator.mjs',
  'scripts/release-plan.mjs',
]);

const PROTECTED_SEGMENT_PATTERNS: readonly RegExp[] = [
  /^\.githooks$/iu,
  /^\.git$/iu,
  /^\.ssh$/iu,
  /^id_rsa(?:\..+)?$/iu,
  /^id_ed25519(?:\..+)?$/iu,
  /^\.npmrc$/iu,
  /^\.netrc$/iu,
];

const SECRET_EXTENSIONS: readonly string[] = ['.pem', '.key', '.p12', '.pfx', '.kdbx'];

const DESTRUCTIVE_SHELL_PATTERNS: readonly { readonly reason: string; readonly regex: RegExp }[] = [
  {
    reason: 'destructive recursive delete (rm -rf)',
    regex: /\brm\s+[^\n]*(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive\s+--force|--force\s+--recursive)/iu,
  },
  {
    reason: 'destructive PowerShell recursive delete',
    regex: /\bremove-item\b[^\n]*(-recurse[^\n]*-force|-force[^\n]*-recurse)/iu,
  },
  {
    reason: 'destructive git reset --hard',
    regex: /\bgit\s+reset\s+--hard\b/iu,
  },
  {
    reason: 'destructive git force push',
    regex: /\bgit\s+push\b[^\n]*(\s--force\b|\s-f\b|\s--force-with-lease\b)/iu,
  },
  {
    reason: 'protected git hooks referenced in shell command',
    regex: /(^|[\s"'/\\])\.githooks([/\\]|$|\s|"|')|(^|[\s"'/\\])\.git[/\\]hooks([/\\]|$|\s|"|')/iu,
  },
  {
    reason: 'protected .env file referenced in shell command',
    regex: /(^|[\s"'/\\])\.env(\.[a-z0-9_-]+)?($|[\s"'|;&>])/iu,
  },
];

const EGRESS_SHELL_PATTERNS: readonly RegExp[] = [
  /\b(curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm|ssh|scp|sftp|rsync|nc|netcat)\b/iu,
  /\bgit\s+(push|pull|fetch|clone)\b/iu,
  /\b((npm|pnpm|bun|yarn)\s+publish|docker\s+(push|pull|login)|gh\s+(pr|release|api|repo))\b/iu,
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function normalizeTargetPath(rawPath: string): string {
  const slashed = rawPath.trim().replaceAll('\\', '/');
  let normalized = slashed;
  while (normalized.startsWith('./')) {
    normalized = normalized.slice(2);
  }
  while (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

export function isProtectedGovernanceOrSecretPath(rawPath: string): boolean {
  const normalized = normalizeTargetPath(rawPath);
  if (normalized.length === 0) {
    return false;
  }
  const lowered = normalized.toLowerCase();
  for (const protectedPath of PROTECTED_EXACT_PATHS) {
    if (lowered === protectedPath || lowered.endsWith(`/${protectedPath}`)) {
      return true;
    }
  }
  const segments = lowered.split('/');
  for (const segment of segments) {
    if (segment === '..') {
      return true;
    }
    if (
      segment === '.env' ||
      (segment.startsWith('.env.') &&
        segment !== '.env.example' &&
        segment !== '.env.sample' &&
        segment !== '.env.template')
    ) {
      return true;
    }
    if (PROTECTED_SEGMENT_PATTERNS.some((pattern) => pattern.test(segment))) {
      return true;
    }
    if (SECRET_EXTENSIONS.some((ext) => segment.endsWith(ext))) {
      return true;
    }
  }
  return false;
}

export function extractTargetPaths(args: Record<string, unknown>): string[] {
  const paths: string[] = [];
  const candidateKeys = ['path', 'filePath', 'file_path', 'target', 'file', 'destination'];
  for (const key of candidateKeys) {
    const val = args[key];
    if (typeof val === 'string' && val.trim().length > 0) {
      paths.push(normalizeTargetPath(val));
    }
  }
  const listKeys = ['paths', 'files', 'targetPaths'];
  for (const key of listKeys) {
    const val = args[key];
    if (Array.isArray(val)) {
      for (const entry of val) {
        if (typeof entry === 'string' && entry.trim().length > 0) {
          paths.push(normalizeTargetPath(entry));
        }
      }
    }
  }
  return [...new Set(paths)];
}

export function extractCommand(args: Record<string, unknown>): string {
  const candidateKeys = ['command', 'cmd', 'script'];
  for (const key of candidateKeys) {
    const val = args[key];
    if (typeof val === 'string' && val.trim().length > 0) {
      return val.trim();
    }
  }
  return '';
}

function classifyToolInvocation(
  toolName: string,
  targetPaths: readonly string[],
  command: string
): {
  readonly action: string;
  readonly capability: string;
  readonly tier: RiskTier;
  readonly targetZone: TargetZone;
  readonly localBlockReason?: string;
} {
  const normalizedTool = toolName.trim().toLowerCase();

  for (const p of targetPaths) {
    if (isProtectedGovernanceOrSecretPath(p)) {
      return {
        action: 'protected_path_access',
        capability: `tool.${normalizedTool}`,
        tier: 'R4',
        targetZone: 'local',
        localBlockReason: `Protected governance or secret path blocked: "${p}".`,
      };
    }
  }

  if (command.length > 0) {
    const sanitized = command
      .toLowerCase()
      .replaceAll('.env.example', '__env_example__')
      .replaceAll('.env.sample', '__env_sample__')
      .replaceAll('.env.template', '__env_template__');

    for (const rule of DESTRUCTIVE_SHELL_PATTERNS) {
      if (rule.regex.test(sanitized)) {
        return {
          action: 'unrestricted_shell',
          capability: 'shell.exec',
          tier: 'R4',
          targetZone: 'local',
          localBlockReason: `Destructive or protected-surface shell command blocked: ${rule.reason}.`,
        };
      }
    }
    if (EGRESS_SHELL_PATTERNS.some((pattern) => pattern.test(command))) {
      return {
        action: 'external_http',
        capability: 'network.egress',
        tier: 'R3',
        targetZone: 'cloud',
      };
    }
  }

  switch (normalizedTool) {
    case 'read':
    case 'read_file':
    case 'list':
    case 'list_dir':
    case 'glob':
    case 'grep':
    case 'grep_search':
    case 'search_symbols':
      return {
        action: 'read_file',
        capability: 'workspace.read',
        tier: 'R0',
        targetZone: 'local',
      };
    case 'write':
    case 'write_file':
    case 'edit':
    case 'edit_file':
    case 'patch':
    case 'apply_patch':
    case 'multiedit':
      return {
        action: 'edit_file',
        capability: 'workspace.write',
        tier: 'R1',
        targetZone: 'local',
      };
    case 'bash':
    case 'shell':
    case 'run_shell':
    case 'exec':
      return {
        action: 'run_command',
        capability: 'workspace.exec',
        tier: 'R2',
        targetZone: 'local',
      };
    case 'webfetch':
    case 'web_fetch':
    case 'http_request':
    case 'mcp_call':
      return {
        action: 'external_http',
        capability: 'network.egress',
        tier: 'R3',
        targetZone: 'cloud',
      };
    default:
      if (normalizedTool.startsWith('mcp_') || normalizedTool.startsWith('remote_')) {
        return {
          action: 'external_http',
          capability: `mcp.${normalizedTool}`,
          tier: 'R3',
          targetZone: 'cloud',
        };
      }
      return {
        action: normalizedTool || 'unknown_tool',
        capability: `tool.${normalizedTool || 'unknown'}`,
        tier: 'R3',
        targetZone: 'local',
      };
  }
}

export async function resolveRidBearerToken(options: {
  readonly tokenFilePath?: string;
  readonly getBearerToken?: () => Promise<string | null> | string | null;
}): Promise<string | null> {
  if (options.getBearerToken !== undefined) {
    const custom = await options.getBearerToken();
    if (typeof custom === 'string' && custom.trim().length > 0) {
      return custom.trim();
    }
    return null;
  }

  const envToken = (process.env.ROCKSOUL_TOKEN ?? process.env.MW_RID_ACCESS_TOKEN ?? '').trim();
  if (envToken.length > 0) {
    return envToken;
  }

  const tokenPath =
    options.tokenFilePath ??
    process.env.ROCKSOUL_TOKEN_PATH ??
    join(process.env.ROCKSOUL_HOME ?? join(homedir(), '.rocksoul'), 'token.json');

  try {
    const raw = await readFile(tokenPath, 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed) || typeof parsed.access_token !== 'string') {
      return null;
    }
    const accessToken = parsed.access_token.trim();
    if (accessToken.length === 0) {
      return null;
    }
    if (typeof parsed.expires_at === 'string' && parsed.expires_at.trim().length > 0) {
      const expiresMs = Date.parse(parsed.expires_at);
      if (Number.isFinite(expiresMs) && expiresMs <= Date.now()) {
        return null;
      }
    }
    return accessToken;
  } catch {
    return null;
  }
}

export async function injectRidBearerHeaders(
  headers: Record<string, string>,
  options: RocksoulPluginOptions = {}
): Promise<Record<string, string>> {
  const token = await resolveRidBearerToken({
    tokenFilePath: options.tokenFilePath,
    getBearerToken: options.getBearerToken,
  });

  headers['X-MW-Agent'] = options.agentHeader ?? DEFAULT_AGENT_HEADER;
  if (options.dataClassification !== undefined) {
    headers['X-Rocksoul-Data-Classification'] = options.dataClassification;
  }
  if (token !== null && !headers.Authorization && !headers.authorization) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

function parseCoreDecision(raw: unknown): CoreRiskEvaluateDecision | null {
  if (!isRecord(raw)) {
    return null;
  }
  if (
    typeof raw.allowed !== 'boolean' ||
    (raw.decision !== 'allow' &&
      raw.decision !== 'require_human_approval' &&
      raw.decision !== 'deny') ||
    typeof raw.effectiveRiskTier !== 'string' ||
    !Array.isArray(raw.reasonCodes) ||
    !Array.isArray(raw.messages)
  ) {
    return null;
  }
  const reasonCodes = raw.reasonCodes.filter((item): item is string => typeof item === 'string');
  const messages = raw.messages.filter((item): item is string => typeof item === 'string');
  const dataClassification: DataClassification =
    raw.dataClassification === 'cloud_eligible' ? 'cloud_eligible' : 'local_only';
  const targetZone: TargetZone = raw.targetZone === 'cloud' ? 'cloud' : 'local';

  return {
    allowed: raw.allowed,
    decision: raw.decision,
    effectiveRiskTier: raw.effectiveRiskTier as RiskTier,
    dataClassification,
    targetZone,
    reasonCodes,
    messages,
  };
}

/**
 * Creates OpenCode plugin hooks backed by mw-rocksoul-core (:4520/v1/risk/evaluate)
 * with fail-closed R0-R4 protection, governance path blocking, and mw-rid Bearer injection.
 */
export function createRocksoulOpenCodePlugin(
  options: RocksoulPluginOptions = {}
): RocksoulOpenCodeHooks {
  const coreBaseUrl = (
    options.coreBaseUrl ??
    process.env.ROCKSOUL_CORE_URL ??
    DEFAULT_CORE_BASE_URL
  ).replace(/\/+$/u, '');
  const principalId = options.principalId ?? DEFAULT_PRINCIPAL_ID;
  const dataClassification: DataClassification = options.dataClassification ?? 'local_only';
  const readOnlyMode = options.readOnlyMode ?? false;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchFn = options.fetchImpl ?? fetch;

  return {
    'chat.headers': async (_input: ChatHeadersInput, output: ChatHeadersOutput): Promise<void> => {
      await injectRidBearerHeaders(output.headers, options);
    },

    'tool.execute.before': async (
      input: ToolExecuteBeforeInput,
      output: ToolExecuteBeforeOutput
    ): Promise<void> => {
      const args = isRecord(output.args) ? output.args : {};
      const targetPaths = extractTargetPaths(args);
      const command = extractCommand(args);
      const classified = classifyToolInvocation(input.tool, targetPaths, command);

      // Fail-closed local hard block for R4 governance/protected files & destructive shell commands.
      if (classified.localBlockReason !== undefined) {
        throw new RocksoulPolicyError(
          classified.localBlockReason,
          'R4',
          'deny',
          ['PROTECTED_PATH_BLOCKED', 'PROHIBITED_RISK_TIER_R4']
        );
      }

      const payload: CoreRiskEvaluateRequest = {
        principalId,
        action: classified.action,
        capability: classified.capability,
        requestedTier: classified.tier,
        dataClassification,
        targetZone: classified.targetZone,
        ...(targetPaths.length > 0 ? { targetPaths } : {}),
        ...(readOnlyMode ? { readOnlyMode: true } : {}),
      };

      const headers = await injectRidBearerHeaders(
        {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        options
      );

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let response: Response;
      try {
        response = await fetchFn(`${coreBaseUrl}/v1/risk/evaluate`, {
          method: 'POST',
          headers,
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        throw new RocksoulPolicyError(
          `Fail-closed: mw-rocksoul-core risk policy unreachable at ${coreBaseUrl} (${detail}).`,
          classified.tier,
          'deny',
          ['CORE_POLICY_UNAVAILABLE']
        );
      } finally {
        clearTimeout(timer);
      }

      if (!response.ok) {
        throw new RocksoulPolicyError(
          `Fail-closed: mw-rocksoul-core returned HTTP ${response.status} during risk evaluation.`,
          classified.tier,
          'deny',
          ['CORE_POLICY_HTTP_ERROR']
        );
      }

      let rawBody: unknown;
      try {
        rawBody = await response.json();
      } catch {
        throw new RocksoulPolicyError(
          'Fail-closed: mw-rocksoul-core returned malformed JSON during risk evaluation.',
          classified.tier,
          'deny',
          ['CORE_POLICY_MALFORMED_RESPONSE']
        );
      }

      const decision = parseCoreDecision(rawBody);
      if (decision === null) {
        throw new RocksoulPolicyError(
          'Fail-closed: mw-rocksoul-core returned an invalid risk decision envelope.',
          classified.tier,
          'deny',
          ['CORE_POLICY_INVALID_DECISION']
        );
      }

      if (!decision.allowed) {
        const explanation =
          decision.messages.length > 0
            ? decision.messages.join(' ')
            : `Tool "${input.tool}" blocked under ${decision.effectiveRiskTier} (${decision.decision}).`;
        throw new RocksoulPolicyError(
          explanation,
          decision.effectiveRiskTier,
          decision.decision,
          decision.reasonCodes
        );
      }
    },
  };
}

/**
 * Default OpenCode plugin entrypoint compatible with OpenCode's async plugin loader.
 */
export async function RocksoulOpenCodePlugin(): Promise<RocksoulOpenCodeHooks> {
  return createRocksoulOpenCodePlugin();
}

export default RocksoulOpenCodePlugin;
