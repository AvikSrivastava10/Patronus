import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectProject } from '../src/index.js';
import { TOOL } from '../src/constants.js';

let dir;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'patronus-detect-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(rel, content = '') {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

describe('detectProject', () => {
  it('detects a Node project and enables npm audit + eslint + semgrep', () => {
    write('package.json', '{"name":"x"}');
    write('index.js', 'console.log(1)');
    const d = detectProject(dir);
    expect(d.stacks.node).toBe(true);
    expect(d.languages).toContain('javascript');
    expect(d.enabledTools.has(TOOL.npmAudit)).toBe(true);
    expect(d.enabledTools.has(TOOL.eslint)).toBe(true);
    expect(d.enabledTools.has(TOOL.semgrep)).toBe(true);
    // No python tools on a pure JS project.
    expect(d.enabledTools.has(TOOL.bandit)).toBe(false);
    expect(d.enabledTools.has(TOOL.pipAudit)).toBe(false);
  });

  it('detects a Python project and enables pip-audit + bandit, not npm/eslint', () => {
    write('requirements.txt', 'flask==0.5');
    write('app.py', 'print(1)');
    const d = detectProject(dir);
    expect(d.stacks.python).toBe(true);
    expect(d.languages).toContain('python');
    expect(d.enabledTools.has(TOOL.pipAudit)).toBe(true);
    expect(d.enabledTools.has(TOOL.bandit)).toBe(true);
    expect(d.enabledTools.has(TOOL.npmAudit)).toBe(false);
    expect(d.enabledTools.has(TOOL.eslint)).toBe(false);
  });

  it('enables gitleaks + trufflehog when a .git directory exists', () => {
    write('package.json', '{}');
    fs.mkdirSync(path.join(dir, '.git'));
    const d = detectProject(dir);
    expect(d.stacks.git).toBe(true);
    expect(d.enabledTools.has(TOOL.gitleaks)).toBe(true);
    expect(d.enabledTools.has(TOOL.trufflehog)).toBe(true);
  });

  it('enables Trivy for Docker/Terraform/K8s markers', () => {
    write('Dockerfile', 'FROM node:20');
    write('main.tf', 'resource "aws_s3_bucket" "b" {}');
    const d = detectProject(dir);
    expect(d.stacks.docker).toBe(true);
    expect(d.stacks.terraform).toBe(true);
    expect(d.enabledTools.has(TOOL.trivy)).toBe(true);
  });

  it('detects Kubernetes manifests via kind + apiVersion', () => {
    write('deploy.yaml', 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n');
    const d = detectProject(dir);
    expect(d.stacks.kubernetes).toBe(true);
    expect(d.enabledTools.has(TOOL.trivy)).toBe(true);
  });

  it('does not misclassify a plain YAML file as a k8s manifest', () => {
    write('config.yaml', 'name: myapp\nversion: 1\n');
    const d = detectProject(dir);
    expect(d.stacks.kubernetes).toBe(false);
  });

  it('enables OWASP Dependency-Check for Java/.NET manifests', () => {
    write('pom.xml', '<project></project>');
    const d = detectProject(dir);
    expect(d.stacks.java).toBe(true);
    expect(d.enabledTools.has(TOOL.owaspDependencyCheck)).toBe(true);
  });

  it('reports an empty tool set for a directory with no markers', () => {
    write('notes.txt', 'hello');
    const d = detectProject(dir);
    expect(d.stacks.node).toBe(false);
    expect(d.enabledTools.has(TOOL.semgrep)).toBe(false);
  });
});
