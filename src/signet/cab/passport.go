package cab

// Crypto Attestation / Passport (cab) claim builder placeholder.

import "os"

type Passport struct {
	Provider   string `json:"prov"`
	ProviderVer string `json:"provider_ver"`
	FIPS       bool   `json:"fips_mode"`
}

func Gather() Passport {
	return Passport{
		Provider: "openssl", // placeholder
		ProviderVer: os.Getenv("OPENSSL_VERSION"),
		FIPS: false,
	}
}
