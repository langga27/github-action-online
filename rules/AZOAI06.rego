package rules

deny[msg] {
	resource := input.resource.azurerm_cognitive_account[name]
	resource.kind == "OpenAI"
	not resource.customer_managed_key

	msg := {
		# Mandatory fields
		"publicId": "AZOAI06",
		"title": "AZOAI06: Encryption at Rest",
		"severity": "high",
		"msg": sprintf("resource.azurerm_cognitive_account[%s]", [name]),
		"issue": "Azure OpenAI must be configured to use Customer Managed Keys (CMEK).",
		"impact": "If CMEK is not used, there is a risk where data can be exfiltrated and read by malicious actor, upon obtaining the microsoft encryption key and the encrypted data.",
        "remediation": "Please enable CMEK when provisioning Azure OpenAI. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
	}
}