#!/usr/bin/env python3
"""
Claude Code Security Audit & Hook Hijacking Hardening Tool
Author: Elena Rostova, Staff Agentic Systems Engineer
Affiliation: EyesTech Systems Lab (https://eyestech.in)
License: MIT
Reference Publication: https://eyestech.in/claude-code-token-compromise-hook-security-audit/
"""

import os
import sys
import json
import argparse
from typing import Dict, List, Any


class ClaudeCodeAuditor:
    """
    Scans local repositories and Claude Code configurations for pre-trust execution
    vulnerabilities, CVE-2026-21852 hook hijacking, and token leakage vectors.
    """
    def __init__(self, workspace_path: str):
        self.workspace_path = os.path.abspath(workspace_path)
        self.findings: List[Dict[str, Any]] = []

    def audit_hook_configurations(self):
        """Scans for untrusted .claude/hooks.json or settings.json hook scripts."""
        claude_dir = os.path.join(self.workspace_path, ".claude")
        if not os.path.exists(claude_dir):
            return

        suspicious_keys = ["pre_command", "post_tool_call", "base_url_override", "api_proxy"]

        for filename in ["hooks.json", "settings.json", "config.json"]:
            filepath = os.path.join(claude_dir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for key in suspicious_keys:
                            if key in data:
                                self.findings.append({
                                    "severity": "CRITICAL",
                                    "vuln_id": "CVE-2026-21852-HOOK-HIJACK",
                                    "title": f"Pre-Trust Execution Hook Present: '{key}'",
                                    "description": f"Found hook definition in {filepath} that executes before prompt trust confirmation.",
                                    "remediation": "Audit the hook script command line and ensure hooks are only loaded from trusted global user directories, not untrusted repositories."
                                })
                except Exception:
                    pass

    def audit_base_url_redirect(self):
        """Checks for ANTHROPIC_BASE_URL redirection in environment or dotenv."""
        for root, _, files in os.walk(self.workspace_path):
            for file in files:
                if file in [".env", ".env.local", ".bashrc", ".zshrc"]:
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                if "ANTHROPIC_BASE_URL" in line and not line.strip().startswith("#"):
                                    if "api.anthropic.com" not in line:
                                        self.findings.append({
                                            "severity": "HIGH",
                                            "vuln_id": "BASE-URL-PROXY-HIJACK",
                                            "title": "Non-Standard Anthropic Base URL Configured",
                                            "description": f"File {filepath} redirects ANTHROPIC_BASE_URL to an unverified proxy: {line.strip()}",
                                            "remediation": "Verify proxy authenticity to ensure API auth tokens are not exfiltrated."
                                        })
                    except Exception:
                        pass

    def generate_ebpf_containment_profile(self) -> str:
        """Outputs an eBPF socket filtering policy to lock down coding agents."""
        return """# eBPF / iptables Outbound Agent Egress Lockdown
# Allows outbound HTTPS ONLY to verified API endpoints
sudo iptables -N AGENT_EGRESS_FILTER
sudo iptables -A AGENT_EGRESS_FILTER -p tcp -m tcp --dport 53 -j ACCEPT  # DNS
sudo iptables -A AGENT_EGRESS_FILTER -d api.anthropic.com -p tcp --dport 443 -j ACCEPT
sudo iptables -A AGENT_EGRESS_FILTER -d api.openai.com -p tcp --dport 443 -j ACCEPT
sudo iptables -A AGENT_EGRESS_FILTER -d github.com -p tcp --dport 443 -j ACCEPT
sudo iptables -A AGENT_EGRESS_FILTER -j REJECT --reject-with tcp-reset
"""

    def run_all(self) -> List[Dict[str, Any]]:
        self.audit_hook_configurations()
        self.audit_base_url_redirect()
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Claude Code Security Audit & CVE-2026-21852 Hardening Tool"
    )
    parser.add_argument("path", nargs="?", default=".", help="Workspace directory to audit.")
    parser.add_argument("--gen-ebpf", action="store_true", help="Output eBPF network containment profile.")
    args = parser.parse_args()

    print("=" * 80)
    print("EYESTECH SYSTEMS LAB - CLAUDE CODE CVE-2026-21852 SECURITY SCANNER")
    print(f"Target: {os.path.abspath(args.path)}")
    print("Reference Audit: https://eyestech.in/claude-code-token-compromise-hook-security-audit/")
    print("=" * 80)

    auditor = ClaudeCodeAuditor(args.path)
    findings = auditor.run_all()

    if not findings:
        print("\n [HARDENING VALIDATED]: No hook hijacking or token redirect vectors detected.")
    else:
        print(f"\n⚠️  DETECTED {len(findings)} AGENT SECURITY RISKS:\n")
        for f in findings:
            print(f"[{f['severity']}] {f['vuln_id']}: {f['title']}")
            print(f"  Details:     {f['description']}")
            print(f"  Remediation: {f['remediation']}\n")

    if args.gen_ebpf:
        print("\n--- RECOMMENDED NETWORK CONTAINMENT POLICY ---")
        print(auditor.generate_ebpf_containment_profile())
    print("=" * 80)


if __name__ == "__main__":
    main()
