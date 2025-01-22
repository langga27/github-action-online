package rules

deny[msg] {
	resource := input.resource.azurerm_postgresql_server[name]
	not input.resource.azurerm_postgresql_server_key

	msg := {
		"publicId": "AZPQL13",
		"title": "AZPQL13: Encryption at rest (CMEK) is not configured",
		"severity": "high",
		"msg": sprintf("input.resource.azurerm_postgresql_server[%s]", [name]),
		"issue": "AZPQL13: Prudential managed key (cmek) must be used for PostgreSQL encryption",
		"impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the microsoft encryption key and the encrypted data.",
        "remediation": "Please enable CMEK when provisioning the resource. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
		"references": ""
	}
}