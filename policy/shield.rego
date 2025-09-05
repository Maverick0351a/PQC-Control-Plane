package signet.shield

default allow = false

allow {
  input.cfg.safety.require_tls_exporter == false
}
allow {
  input.obs.binding_type == "tls-exporter"
}

fallback {
  input.obs.ewma_5xx > input.cfg.safety.availability_floor_5xx_ewma
}

enforce_allowed {
  allow
  not fallback
}
