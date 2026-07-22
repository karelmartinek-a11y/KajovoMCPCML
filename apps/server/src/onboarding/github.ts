import { createSign } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type { GitHubOnboardingConfig } from "../config.js";

type GitHubResponse = Record<string, unknown>;

export const REQUIRED_ONBOARDING_CHECKS = [
  "path-policy",
  "manifest-schema",
  "lint",
  "typecheck",
  "unit-tests",
  "contract-tests",
  "secret-scan",
  "sast",
  "sca-license",
  "sbom",
  "reproducible-build"
] as const;

function base64url(value: string): string {
  return Buffer.from(value).toString("base64url");
}

function githubAppJwt(config: GitHubOnboardingConfig): string {
  if (!config.GITHUB_APP_ID || !config.GITHUB_APP_PRIVATE_KEY_BASE64) throw new Error("github_app_not_configured");
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({ iat: now - 60, exp: now + 9 * 60, iss: config.GITHUB_APP_ID }));
  const content = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(content);
  const signature = signer.sign(Buffer.from(config.GITHUB_APP_PRIVATE_KEY_BASE64, "base64").toString("utf8"), "base64url");
  return `${content}.${signature}`;
}

export class GitHubOnboardingClient {
  private token: { value: string; expiresAt: number } | null = null;

  constructor(private readonly config: GitHubOnboardingConfig) {}

  private async accessToken(): Promise<string> {
    if (this.config.GITHUB_TOKEN) return this.config.GITHUB_TOKEN;
    if (this.token && this.token.expiresAt > Date.now() + 60_000) return this.token.value;
    if (!this.config.GITHUB_APP_INSTALLATION_ID) throw new Error("github_app_not_configured");
    const response = await fetch(`https://api.github.com/app/installations/${this.config.GITHUB_APP_INSTALLATION_ID}/access_tokens`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${githubAppJwt(this.config)}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "KajovoCML-onboarding-worker"
      }
    });
    if (!response.ok) throw new Error(`github_installation_token_failed:${response.status}`);
    const body = await response.json() as { token?: string; expires_at?: string };
    if (!body.token || !body.expires_at) throw new Error("github_installation_token_invalid");
    this.token = { value: body.token, expiresAt: new Date(body.expires_at).getTime() };
    return body.token;
  }

  private async request(method: string, endpoint: string, body?: unknown): Promise<GitHubResponse> {
    const token = await this.accessToken();
    const response = await fetch(`https://api.github.com${endpoint}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "content-type": "application/json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "KajovoCML-onboarding-worker"
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    if (!response.ok) {
      const detail = await response.text();
      throw Object.assign(new Error(`github_api_failed:${method}:${endpoint}:${response.status}:${detail.slice(0, 300)}`), { statusCode: response.status });
    }
    if (response.status === 204) return {};
    return response.json() as Promise<GitHubResponse>;
  }

  private repoPath(endpoint: string): string {
    if (!this.config.GITHUB_OWNER || !this.config.GITHUB_REPO) throw new Error("github_app_not_configured");
    return `/repos/${this.config.GITHUB_OWNER}/${this.config.GITHUB_REPO}${endpoint}`;
  }

  async createPullRequest(input: {
    jobId: string;
    code: string;
    sourceDirectory: string;
    sourceDigest: string;
    manifestDigest: string;
  }): Promise<{ branch: string; pullNumber: number; pullUrl: string; headSha: string }> {
    const branch = `integration/${input.code.toLowerCase()}/${input.jobId}`;
    const root = await this.request("GET", this.repoPath("/git/ref/heads/main"));
    const object = root.object as { sha?: string } | undefined;
    if (!object?.sha) throw new Error("github_main_ref_missing");
    const baseCommitSha = object.sha;
    const commit = await this.request("GET", this.repoPath(`/git/commits/${baseCommitSha}`));
    const baseTree = (commit.tree as { sha?: string } | undefined)?.sha;
    if (!baseTree) throw new Error("github_main_tree_missing");
    const sourceFiles = await listFiles(input.sourceDirectory);
    const treeEntries: Array<Record<string, unknown>> = [];
    for (const relative of sourceFiles) {
      const content = await fs.readFile(path.join(input.sourceDirectory, relative));
      const blob = await this.request("POST", this.repoPath("/git/blobs"), { content: content.toString("base64"), encoding: "base64" });
      treeEntries.push({ path: `handlers/${input.code}/${relative.replaceAll(path.sep, "/")}`, mode: "100644", type: "blob", sha: blob.sha });
    }
    const metadata = Buffer.from(JSON.stringify({
      jobId: input.jobId,
      code: input.code,
      sourceDigest: input.sourceDigest,
      manifestDigest: input.manifestDigest
    }, null, 2));
    const metadataBlob = await this.request("POST", this.repoPath("/git/blobs"), { content: metadata.toString("base64"), encoding: "base64" });
    treeEntries.push({ path: `handlers/${input.code}/.kcml-onboarding.json`, mode: "100644", type: "blob", sha: metadataBlob.sha });
    const tree = await this.request("POST", this.repoPath("/git/trees"), { base_tree: baseTree, tree: treeEntries });
    const createdCommit = await this.request("POST", this.repoPath("/git/commits"), {
      message: `feat(${input.code}): add isolated MCP handler`,
      tree: tree.sha,
      parents: [baseCommitSha]
    });
    const headSha = String(createdCommit.sha);
    try {
      await this.request("POST", this.repoPath("/git/refs"), { ref: `refs/heads/${branch}`, sha: headSha });
    } catch (error) {
      if (Number((error as { statusCode?: number }).statusCode) !== 422) throw error;
      await this.request("PATCH", this.repoPath(`/git/refs/heads/${branch}`), { sha: headSha, force: true });
    }
    const existing = await this.request("GET", this.repoPath(`/pulls?state=open&head=${encodeURIComponent(`${this.config.GITHUB_OWNER}:${branch}`)}`));
    const pulls = existing as unknown as Array<Record<string, unknown>>;
    const pull = pulls[0] ?? await this.request("POST", this.repoPath("/pulls"), {
      title: `${input.code}: automated MCP onboarding`,
      head: branch,
      base: "main",
      body: `Automated onboarding job \`${input.jobId}\`. Source digest: \`${input.sourceDigest}\`.\n\nOnly \`handlers/${input.code}/\` may change.`
    });
    return {
      branch,
      pullNumber: Number(pull.number),
      pullUrl: String(pull.html_url),
      headSha
    };
  }

  async checkPullRequest(pullNumber: number): Promise<{
    state: "pending" | "pass" | "fail";
    headSha: string;
    checks: Array<{ name: string; status: string; conclusion: string | null; url: string | null }>;
  }> {
    const pull = await this.request("GET", this.repoPath(`/pulls/${pullNumber}`));
    const headSha = String((pull.head as { sha?: string } | undefined)?.sha ?? "");
    if (!headSha) throw new Error("github_pr_head_missing");
    const response = await this.request("GET", this.repoPath(`/commits/${headSha}/check-runs?per_page=100`));
    const checks = ((response.check_runs ?? []) as Array<Record<string, unknown>>).map((check) => ({
      name: String(check.name),
      status: String(check.status),
      conclusion: typeof check.conclusion === "string" ? check.conclusion : null,
      url: typeof check.html_url === "string" ? check.html_url : null
    }));
    if (String(pull.state) !== "open") return { state: "fail", headSha, checks };
    const byName = new Map(checks.map((check) => [check.name, check]));
    const required = REQUIRED_ONBOARDING_CHECKS.map((name) => byName.get(name));
    if (required.some((check) => !check || check.status !== "completed")) return { state: "pending", headSha, checks };
    if (required.some((check) => check?.conclusion !== "success")) return { state: "fail", headSha, checks };
    return { state: "pass", headSha, checks };
  }

  async mergePullRequest(pullNumber: number, expectedHeadSha: string): Promise<{ mergeSha: string }> {
    const merged = await this.request("PUT", this.repoPath(`/pulls/${pullNumber}/merge`), {
      commit_title: `Automated MCP onboarding (#${pullNumber})`,
      merge_method: "squash",
      sha: expectedHeadSha
    });
    if (!merged.merged || !merged.sha) throw new Error("github_pr_merge_failed");
    return { mergeSha: typeof merged.sha === "string" ? merged.sha : "" };
  }

  async checkTrustedBuild(headSha: string): Promise<{
    state: "pending" | "pass" | "fail";
    runId: string | null;
    runUrl: string | null;
    conclusion: string | null;
  }> {
    const response = await this.request(
      "GET",
      this.repoPath(`/actions/runs?head_sha=${encodeURIComponent(headSha)}&event=push&per_page=100`)
    );
    const runs = ((response.workflow_runs ?? []) as Array<Record<string, unknown>>)
      .filter((run) => run.name === "Build signed MCP handler images" && run.head_sha === headSha);
    const latest = runs[0];
    if (!latest) return { state: "pending", runId: null, runUrl: null, conclusion: null };
    const runId = String(latest.id);
    const runUrl = typeof latest.html_url === "string" ? latest.html_url : null;
    const status = typeof latest.status === "string" ? latest.status : "";
    const conclusion = typeof latest.conclusion === "string" ? latest.conclusion : null;
    if (status !== "completed") return { state: "pending", runId, runUrl, conclusion };
    return { state: conclusion === "success" ? "pass" : "fail", runId, runUrl, conclusion };
  }
}

async function listFiles(root: string, current = ""): Promise<string[]> {
  const directory = path.join(root, current);
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of [...entries].sort((left, right) => left.name.localeCompare(right.name))) {
    const relative = path.join(current, entry.name);
    if (entry.isDirectory()) files.push(...await listFiles(root, relative));
    else if (entry.isFile()) files.push(relative);
    else throw new Error("source_tree_contains_special_file");
  }
  return files;
}
