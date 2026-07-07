---
name: validator
type: rules
description: Validates enterprise SAST & VAPT security report. Checks all six mandatory documents, all finding fields, compliance standards, and Checkmarx card format headings.
---

## Rules

# ── Required Header ───────────────────────────────────────────────────────────

- id: required_header
  severity: error
  check: contains
  pattern: "# Security Report"
  message: "Missing required header: # Security Report"

# ── Six Mandatory Documents (Enterprise SAST & VAPT Standards Section 9) ──────

- id: required_document_1
  severity: error
  check: contains
  pattern: "## Document 1: Security Standards Compliance Report"
  message: "Missing required section: ## Document 1: Security Standards Compliance Report"

- id: required_document_2
  severity: error
  check: contains
  pattern: "## Document 2: Illegal Parameters & Secret Exposure Report"
  message: "Missing required section: ## Document 2: Illegal Parameters & Secret Exposure Report"

- id: required_document_3
  severity: error
  check: contains
  pattern: "## Document 3: Executive Security Summary"
  message: "Missing required section: ## Document 3: Executive Security Summary"

- id: required_document_4
  severity: error
  check: contains
  pattern: "## Document 4: Top Vulnerable Files Report"
  message: "Missing required section: ## Document 4: Top Vulnerable Files Report"

- id: required_document_5
  severity: error
  check: contains
  pattern: "## Document 5: Immediate Remediation Plan"
  message: "Missing required section: ## Document 5: Immediate Remediation Plan"

- id: required_document_6
  severity: error
  check: contains
  pattern: "## Document 6: Compliance Mapping Report"
  message: "Missing required section: ## Document 6: Compliance Mapping Report"

# ── Required Sub-Sections ─────────────────────────────────────────────────────

- id: required_executive_summary
  severity: error
  check: contains
  pattern: "## Executive Summary"
  message: "Missing required section: ## Executive Summary (must appear as its own ## heading inside Document 3)"

- id: required_recommended_actions
  severity: error
  check: contains
  pattern: "## Recommended Actions"
  message: "Missing required section: ## Recommended Actions — add this exact heading (character-for-character match required)"

- id: required_forbidden_files
  severity: error
  check: contains
  pattern: "### Forbidden Files Detected"
  message: "Missing required sub-section: ### Forbidden Files Detected (required in Document 2)"

- id: required_hardcoded_secrets
  severity: error
  check: contains
  pattern: "### Hardcoded Secrets Detected"
  message: "Missing required sub-section: ### Hardcoded Secrets Detected (required in Document 2)"

- id: required_illegal_configs
  severity: error
  check: contains
  pattern: "### Illegal Security Configurations Detected"
  message: "Missing required sub-section: ### Illegal Security Configurations Detected (required in Document 2)"

- id: required_sensitive_data
  severity: error
  check: contains
  pattern: "### Sensitive Data Exposure"
  message: "Missing required sub-section: ### Sensitive Data Exposure (required in Document 2)"

# ── Document 2 Evidence Table Columns ────────────────────────────────────────

- id: sensitive_data_table_file_column
  severity: error
  check: contains
  pattern: "Data Type | File | Line | Matched Value | Risk"
  message: "Document 2 Sensitive Data table missing required columns: Data Type | File | Line | Matched Value | Risk"

- id: illegal_configs_table_file_column
  severity: error
  check: contains
  pattern: "File | Line | Configuration | Risk"
  message: "Document 2 Illegal Configs table missing required columns: File | Line | Configuration | Risk"

- id: hardcoded_secrets_table_file_column
  severity: error
  check: contains
  pattern: "Source Line | Destination Line | Source Object | Pattern Matched | Masked Value | Risk"
  message: "Document 2 Hardcoded Secrets table missing required columns"

# ── Required Compliance Standards in Document 1 ───────────────────────────────

- id: required_owasp_top10
  severity: error
  check: contains
  pattern: "OWASP Top 10 2025"
  message: "Document 1 must include OWASP Top 10 2025 compliance status"

- id: required_owasp_api
  severity: error
  check: contains
  pattern: "OWASP API Security Top 10"
  message: "Document 1 must include OWASP API Security Top 10 compliance status"

- id: required_pci_dss
  severity: error
  check: contains
  pattern: "PCI DSS v4.0"
  message: "Document 1 must include PCI DSS v4.0 compliance status"

- id: required_nist
  severity: error
  check: contains
  pattern: "NIST SP 800-53"
  message: "Document 1 must include NIST SP 800-53 compliance status"

- id: required_cwe_top25
  severity: error
  check: contains
  pattern: "CWE Top 25"
  message: "Document 1 must include CWE Top 25 compliance status"

- id: required_sans_top25
  severity: error
  check: contains
  pattern: "SANS Top 25"
  message: "Document 1 must include SANS Top 25 compliance status"

# ── Required Finding Fields for Critical/High Findings ───────────────────────

- id: required_exploitation_scenario
  severity: warning
  check: contains
  pattern: "Exploitation Scenario"
  message: "Critical/High findings must include an Exploitation Scenario (only required when critical or high findings exist)"

- id: required_compliance_violation
  severity: warning
  check: contains
  pattern: "Compliance Violation"
  message: "Critical/High findings must include a Compliance Violation field (only required when critical or high findings exist)"

- id: required_secure_code_recommendation
  severity: warning
  check: contains
  pattern: "Secure Code Recommendation"
  message: "Critical/High findings must include a Secure Code Recommendation (only required when critical or high findings exist)"

- id: required_file_field_in_cards
  severity: error
  check: contains
  pattern: "**File**"
  message: "Critical/High finding cards must include a standalone **File** field with the full relative file path"

# ── Document 6 Compliance Mapping Coverage ────────────────────────────────────

- id: required_compliance_mapping_cwe
  severity: error
  check: contains
  pattern: "CWE"
  message: "Document 6 Compliance Mapping Report must include CWE references"

- id: required_compliance_mapping_owasp
  severity: error
  check: contains
  pattern: "OWASP"
  message: "Document 6 Compliance Mapping Report must include OWASP references"

# ── Language Quality ──────────────────────────────────────────────────────────

- id: no_speculation_1
  severity: warning
  check: regex_absent
  pattern: "(?:may|might|could)\\s+(?:want to|consider|think about)"
  message: "Speculative language found: 'may/might/could want to/consider'"

- id: no_speculation_2
  severity: warning
  check: regex_absent
  pattern: "it\\s+is\\s+(?:recommended|suggested)\\s+that\\s+you"
  message: "Speculative language found: 'it is recommended that you'"

# valid_http_methods removed — HTTP method validation belongs in an API doc
# linter, not a SAST report validator. SAST reports don't document REST endpoints.