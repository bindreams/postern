module github.com/bindreams/postern/provisioner/postern-dns

go 1.23.0

require (
	github.com/libdns/cloudflare v0.1.3
	github.com/libdns/digitalocean v0.0.0-20230728223659-4f9064657aea
	github.com/libdns/gandi v1.0.2
	github.com/libdns/hetzner v0.0.1
	github.com/libdns/libdns v0.2.3
	github.com/libdns/linode v0.4.1
	github.com/libdns/namecheap v0.1.0
	github.com/libdns/ovh v0.0.3
	github.com/libdns/route53 v1.5.1
)

require (
	github.com/aws/aws-sdk-go-v2 v1.30.3 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.27.27 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.27 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.15 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.15 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.42.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.3 // indirect
	github.com/aws/smithy-go v1.20.3 // indirect
	github.com/digitalocean/godo v1.41.0 // indirect
	github.com/go-resty/resty/v2 v2.16.5 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/linode/linodego v1.56.0 // indirect
	github.com/ovh/go-ovh v1.6.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
)

// libdns is a multi-major-version module that mixes v0.x and v1.x under the
// same import path (no /v1 path suffix), so Go's MVS can pick v1.0+ when any
// transitive dep requires it -- but our providers (namecheap v0.1.0, etc) are
// compiled against the v0.2.x Record struct. Pin v0.2.3 explicitly via replace
// so the build resolves to a single, mutually-compatible API.
replace github.com/libdns/libdns => github.com/libdns/libdns v0.2.3
