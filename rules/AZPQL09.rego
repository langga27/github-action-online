package rules

ssl_must_enable(resource) {
  resource.ssl_enforcement_enabled == true
  tls_minimal_version(resource)
}

tls_minimal_version(resource) {
  resource.ssl_minimal_tls_version_enforced == "TLS1_2"
}

tls_minimal_version(resource) {
  resource.ssl_minimal_tls_version_enforced == "TLS1_3"
}

deny[msg] {
  resource := input.resource.azurerm_postgresql_server[name]
  not ssl_must_enable(resource)

  msg := {
    "publicId": "AZPQL09",
    "title": "AZPQL09: TLS version 1.2 is not configured",
    "severity": "high",
    "msg": sprintf("input.resource.azurerm_postgresql_server[%s].ssl_minimal_tls_version_enforced / ssl_enforcement_enabled", [name]),
    "issue": "AZPQL09: SSL must be enabled and minimum TLS version must be 1.2",
    "impact": "Versions lower then TLS 1.2 is susceptible to attack by malicious user.",
    "remediation": "Please use TLS 1.2. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
    "references": ["https://code.pruconnect.net/projects/RTSRETM/repos/postgresql"]
  }
}