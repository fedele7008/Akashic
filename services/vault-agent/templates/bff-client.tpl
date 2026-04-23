{{- with pkiCert "pki-mtls-akashic-ctrl/issue/client"
  "common_name=bff.akashic.local"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/bff/akashic-ctrl-client.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/bff/akashic-ctrl-client.crt" "root" "root" "0644" }}
{{ scratch.Set "chain" "" }}
{{ range .CAChain }}{{ scratch.Set "chain" (printf "%s%s\n" (scratch.Get "chain") .) }}{{ end }}
{{ scratch.Get "chain" | writeToFile "/certs/bff/mtls-ca.crt" "root" "root" "0644" }}
{{- end -}}
