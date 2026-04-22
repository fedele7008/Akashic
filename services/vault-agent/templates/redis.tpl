{{- with pkiCert "pki-internal/issue/server"
  "common_name=redis.akashic.local"
  "alt_names=redis.akashic.local,localhost"
  "ip_sans=127.0.0.1"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/redis/redis.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/redis/redis.crt" "root" "root" "0644" }}
{{ join "" .CAChain | printf "%s\n" | writeToFile "/certs/redis/ca.crt" "root" "root" "0644" }}
{{- end -}}
