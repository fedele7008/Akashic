{{- with pkiCert "pki-internal/issue/server"
  "common_name=loki.akashic.local"
  "alt_names=loki.akashic.local,localhost"
  "ip_sans=127.0.0.1"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/loki-proxy/loki.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/loki-proxy/loki.crt" "root" "root" "0644" }}
{{ scratch.Set "chain" "" }}
{{ range .CAChain }}{{ scratch.Set "chain" (printf "%s%s\n" (scratch.Get "chain") .) }}{{ end }}
{{ scratch.Get "chain" | writeToFile "/certs/loki-proxy/ca.crt" "root" "root" "0644" }}
{{- end -}}
