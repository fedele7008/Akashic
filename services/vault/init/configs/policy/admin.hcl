# ═══════════════════════════════════════════════════════════════
# Policy: admin
# ═══════════════════════════════════════════════════════════════
# Full admin access for human operators via Vault UI or CLI.
# Replaces root token usage for day-to-day administration.
#
# Unlike the root token, userpass tokens:
#   - Expire (configurable TTL)
#   - Are tied to a named identity in audit logs
#   - Can be revoked without affecting other sessions
# ═══════════════════════════════════════════════════════════════

path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
