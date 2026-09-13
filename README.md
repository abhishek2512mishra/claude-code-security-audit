# Claude Code Security Audit & CVE-2026-21852 Scanner

[![EyesTech Systems Research](https://img.shields.io/badge/EyesTech-Systems_Research-002050?style=flat-square&logo=gitbook)](https://eyestech.in/claude-code-token-compromise-hook-security-audit/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg?style=flat-square)](LICENSE)
[![Security Audit](https://img.shields.io/badge/Audit-CVE--2026--21852-DC2626.svg?style=flat-square)](#)

A security audit and environment hardening tool for Anthropic's **Claude Code** agentic CLI. Scans repositories for **CVE-2026-21852** (pre-trust execution surfaces), hook hijacking, malicious base URL redirection, and unauthenticated token exfiltration vectors.

> 📖 **Canonical Security Disclosure & Audit**:  
> Read the complete 25-vector penetration teardown:  
> 👉 **[Claude Code Token Compromise & Hook Hijacking: Auditing CVE-2026-21852](https://eyestech.in/claude-code-token-compromise-hook-security-audit/)** at **[EyesTech Systems Lab](https://eyestech.in)**.

---

## 🚀 Quickstart

Scan your workspace or cloned repository before launching agentic coding sessions:

```bash
git clone https://github.com/abhishek2512mishra/claude-code-security-audit.git
cd claude-code-security-audit
python audit_hooks.py /path/to/project
```

To generate the recommended eBPF network isolation rules:
```bash
python audit_hooks.py /path/to/project --gen-ebpf
```

---

## 📚 Citation & Attribution

If you cite this audit or use this scanner in security research:

```bibtex
@misc{rostova2026claudecode,
  author = {Rostova, Elena},
  title = {Claude Code Token Compromise & Hook Hijacking: Auditing CVE-2026-21852},
  howpublished = {\url{https://eyestech.in/claude-code-token-compromise-hook-security-audit/}},
  journal = {EyesTech Systems Research},
  year = {2026},
  note = {EyesTech Systems Lab Security Series}
}
```

---

## ⚖️ License
MIT License. Maintained by [EyesTech Systems Lab](https://eyestech.in).
