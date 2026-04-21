{{- with pkiCert "pki-internal/issue/server"
  "common_name=postgres.akashic.local"
  "alt_names=postgres.akashic.local,localhost"
  "ip_sans=127.0.0.1"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/postgres/postgres.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/postgres/postgres.crt" "root" "root" "0644" }}
{{ .CA   | writeToFile "/certs/postgres/ca.pem"       "root" "root" "0644" }}
{{- end -}}
