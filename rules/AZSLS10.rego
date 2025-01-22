package rules

minimal_tls_version(resource) {
    resource.minimum_tls_version != "1.2"
}

deny[msg] {
    resource := input.resource.azurerm_mssql_server[name]
    minimal_tls_version(resource)

    msg := {
      # Mandatory fields
      "publicId": "AZSLS10",
      "title": "AZSLS10: TLS version 1.2 is not configured",
      "severity": "high",
      "msg": sprintf("input.resource.azurerm_mssql_server[%s]", [name]),
      # Optional fields
      "issue": "The minimum TLS version on the Azure Storage account must be set to version 1.2",
      "impact": "Versions lower than TLS 1.2 is susceptible to attack by malicious user.",
      "remediation": "Please use TLS 1.2 when provisioning the resource. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
      "references": [""],
    }
}