{{- with pkiCert "pki-mtls-akashic-ctrl/issue/client"
  "common_name=cli.akashic.local"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/akashic-cli/akashic-ctrl-client.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/akashic-cli/akashic-ctrl-client.crt" "root" "root" "0644" }}
{{ scratch.Set "chain" "" }}
{{ range .CAChain }}{{ scratch.Set "chain" (printf "%s%s\n" (scratch.Get "chain") .) }}{{ end }}
{{ scratch.Get "chain" | writeToFile "/certs/akashic-cli/mtls-ca.crt" "root" "root" "0644" }}
{{- end -}}
