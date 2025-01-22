package rules

deny[msg] {
	resource := input.resource.azurerm_cognitive_account[name]
	resource.kind == "FormRecognizer"
    resource.customer_managed_key == []

	msg := {
		# Mandatory fields
		"publicId": "AZFOR03",
		"title": "AZFOR03: Encryption at Rest (CMEK) is not configured",
		"severity": "high",
		"msg": sprintf("resource.azurerm_cognitive_account[%s]", [name]),
		"issue": "Azure Form Recognizer must be configured to use Customer Managed Keys (CMEK).",
		"impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the microsoft encryption key and the encrypted data.",
        "remediation": "Please enable CMEK when provisioning Azure Form Recognizer. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
	}
}