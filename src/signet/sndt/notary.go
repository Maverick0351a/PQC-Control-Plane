package sndt

// Notary emits sndt (service notary decision telemetry) claims.
// Placeholder: integrates with breaker/plan snapshot.

type DecisionSnapshot struct {
	State      string  `json:"state"`
	Rho        float64 `json:"ρ"`
	ErrEWMA    float64 `json:"err_ewma"`
	Decision   string  `json:"decision"`
	Reason     string  `json:"reason"`
}

func BuildClaim(ds DecisionSnapshot) map[string]any {
	return map[string]any{
		"state": ds.State,
		"ρ": ds.Rho,
		"err_ewma": ds.ErrEWMA,
		"decision": ds.Decision,
		"reason": ds.Reason,
	}
}
