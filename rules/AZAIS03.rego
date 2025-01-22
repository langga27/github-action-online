package rules

deny[msg] {
	resource := input.resource.azurerm_cognitive_account[name]
	resource.kind == "SpeechServices"
	not resource.customer_managed_key

	msg := {
		# Mandatory fields
		"publicId": "AZAIS03",
		"title": "AZAIS03: Encryption at Rest (CMEK) is not enabled",
		"severity": "high",
		"msg": sprintf("resource.azurerm_cognitive_account[%s]", [name]),
		"issue": "All Azure Speech Services must be encrypted with customer mananged key (CMEK).",
		"impact": "There is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the microsoft encryption key and the encrypted data.",
        "remediation": "Please enable CMEK when provisioning the Azure Speech Services. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
	}
}