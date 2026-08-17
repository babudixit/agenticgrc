"""One deterministic module per scanner/CSPM/SIEM vendor. Each normalizer
converts vendor-specific finding payloads into UnifiedFinding records (the
common information model the mapping agent consumes). Use
`python -m grc_agent.normalizers.ingress --source …` to route an export to the
right adapter, or call a vendor module directly (tenable / qualys / siem / cspm).
"""
