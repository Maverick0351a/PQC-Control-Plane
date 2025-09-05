package cab

// Crypto Attestation / Passport (cab) claim builder placeholder.

import (
	"os"
)

type Passport struct {
	Provider   string `json:"prov"`
	ProviderVer string `json:"provider_ver"`
	FIPS       bool   `json:"fips_mode"`
}

func Gather() Passport {
	// Prefer env-provided versions; otherwise leave unknown to be filled by Python CBOM if present
	ver := os.Getenv("OPENSSL_VERSION")
	fips := os.Getenv("OPENSSL_FIPS") == "1"
	return Passport{
		Provider:   "openssl",
		ProviderVer: ver,
		FIPS:       fips,
	}
}
