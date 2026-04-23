{{- with pkiCert "pki-internal/issue/server"
  "common_name=auth.akashic.local"
  "alt_names=auth.akashic.local,localhost"
  "ip_sans=127.0.0.1"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/akashic/auth.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/akashic/auth.crt" "root" "root" "0644" }}
{{ scratch.Set "chain" "" }}
{{ range .CAChain }}{{ scratch.Set "chain" (printf "%s%s\n" (scratch.Get "chain") .) }}{{ end }}
{{ scratch.Get "chain" | writeToFile "/certs/akashic/auth-ca.crt" "root" "root" "0644" }}
{{- end -}}
