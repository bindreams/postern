// postern-dns -- thin Lego/libdns-style wrapper for publishing arbitrary TXT records.
//
// Used by the provisioner's Python entrypoint to publish/retire DKIM TXT
// records via the deployer's configured DNS provider.
//
// Subcommands:
//
//	postern-dns txt-set    <fqdn> <value>
//	postern-dns txt-delete <fqdn> <value>
//
// Provider selection: env var DNS_PROVIDER (matches a known provider name).
// Provider config: each provider's native env vars (e.g. CLOUDFLARE_API_TOKEN,
// AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, GANDI_API_TOKEN, DO_AUTH_TOKEN).
// Postern documents the env-var contract per provider in docs/mta.md.
//
// Forward-compat: this binary is intentionally generic. A planned ACME
// DNS-01 cert-renewal feature will add `acme-issue` and `acme-renew`
// subcommands using the same providers; `txt-set`/`txt-delete` stay stable.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/libdns/cloudflare"
	"github.com/libdns/digitalocean"
	"github.com/libdns/gandi"
	"github.com/libdns/hetzner"
	"github.com/libdns/libdns"
	"github.com/libdns/linode"
	"github.com/libdns/namecheap"
	"github.com/libdns/ovh"
	"github.com/libdns/route53"
)

// providerOps is the libdns interface intersection we need.
type providerOps interface {
	libdns.RecordAppender
	libdns.RecordDeleter
}

func newProvider(name string) (providerOps, error) {
	switch strings.ToLower(name) {
	case "cloudflare":
		return &cloudflare.Provider{APIToken: os.Getenv("CLOUDFLARE_API_TOKEN")}, nil
	case "route53":
		return &route53.Provider{
			Region:          os.Getenv("AWS_REGION"),
			AccessKeyId:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		}, nil
	case "gandi":
		return &gandi.Provider{APIToken: os.Getenv("GANDI_API_TOKEN")}, nil
	case "digitalocean":
		return &digitalocean.Provider{APIToken: os.Getenv("DO_AUTH_TOKEN")}, nil
	case "ovh":
		return &ovh.Provider{
			Endpoint:          os.Getenv("OVH_ENDPOINT"),
			ApplicationKey:    os.Getenv("OVH_APPLICATION_KEY"),
			ApplicationSecret: os.Getenv("OVH_APPLICATION_SECRET"),
			ConsumerKey:       os.Getenv("OVH_CONSUMER_KEY"),
		}, nil
	case "hetzner":
		return &hetzner.Provider{AuthAPIToken: os.Getenv("HETZNER_API_TOKEN")}, nil
	case "linode":
		return &linode.Provider{APIToken: os.Getenv("LINODE_TOKEN")}, nil
	case "namecheap":
		return &namecheap.Provider{
			APIKey:      os.Getenv("NAMECHEAP_API_KEY"),
			User:        os.Getenv("NAMECHEAP_API_USER"),
			ClientIP:    os.Getenv("NAMECHEAP_CLIENT_IP"),
		}, nil
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: cloudflare, route53, gandi, digitalocean, ovh, hetzner, linode, namecheap)", name)
	}
}

// splitFQDN takes "postern-2026-04._domainkey.example.com" and returns
// (zone="example.com.", name="postern-2026-04._domainkey"). Best-effort:
// each provider's libdns implementation tolerates an over-specific zone or
// name, so a slightly-wrong split still works in practice.
func splitFQDN(fqdn string) (zone, name string) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return fqdn + ".", "@"
	}
	zone = strings.Join(parts[len(parts)-2:], ".") + "."
	name = strings.Join(parts[:len(parts)-2], ".")
	if name == "" {
		name = "@"
	}
	return zone, name
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  postern-dns txt-set    <fqdn> <value>
  postern-dns txt-delete <fqdn> <value>

env vars:
  DNS_PROVIDER -- provider name (cloudflare, route53, gandi, digitalocean,
                      ovh, hetzner, linode, namecheap)
  Plus the provider's native credential env vars; see docs/mta.md.`)
	os.Exit(2)
}

func main() {
	if len(os.Args) != 4 {
		usage()
	}
	cmd, fqdn, value := os.Args[1], os.Args[2], os.Args[3]
	providerName := os.Getenv("DNS_PROVIDER")
	if providerName == "" || providerName == "none" {
		fmt.Fprintln(os.Stderr, "postern-dns: DNS_PROVIDER not set or set to 'none'")
		os.Exit(1)
	}
	provider, err := newProvider(providerName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "postern-dns:", err)
		os.Exit(1)
	}

	zone, name := splitFQDN(fqdn)
	rec := libdns.Record{
		Type:  "TXT",
		Name:  name,
		Value: value,
		TTL:   5 * time.Minute,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	switch cmd {
	case "txt-set":
		if _, err := provider.AppendRecords(ctx, zone, []libdns.Record{rec}); err != nil {
			fmt.Fprintf(os.Stderr, "postern-dns: txt-set %s: %v\n", fqdn, err)
			os.Exit(1)
		}
	case "txt-delete":
		if _, err := provider.DeleteRecords(ctx, zone, []libdns.Record{rec}); err != nil {
			fmt.Fprintf(os.Stderr, "postern-dns: txt-delete %s: %v\n", fqdn, err)
			os.Exit(1)
		}
	default:
		usage()
	}
}
