{{- with pkiCert "pki-internal/issue/server"
  "common_name=ldap.akashic.local"
  "alt_names=ldap.akashic.local,localhost"
  "ip_sans=127.0.0.1"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/ldap/ldap.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/ldap/ldap.crt" "root" "root" "0644" }}
{{ scratch.Set "chain" "" }}
{{ range .CAChain }}{{ scratch.Set "chain" (printf "%s%s\n" (scratch.Get "chain") .) }}{{ end }}
{{ scratch.Get "chain" | writeToFile "/certs/ldap/ca.crt" "root" "root" "0644" }}
{{- end -}}
