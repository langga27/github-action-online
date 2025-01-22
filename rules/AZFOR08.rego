package rules

deny[msg] {
	resource := input.resource.azurerm_cognitive_account[name]
	resource.kind == "FormRecognizer"
    resource.public_network_access_enabled == true
	not resource.network_acls.ip_rules

	msg := {
		# Mandatory fields
		"publicId": "AZFOR08",
		"title": "AZFOR08: Network Access Control is not restricted",
		"severity": "high",
		"msg": sprintf("resource.azurerm_cognitive_account[%s]", [name]),
		"issue": "All Azure Form Recognizer must not be publically accessible.",
		"impact": "Publically accessible OpenAI may lead to unauthorized access by malicious users.",
        "remediation": "Public access level settings Form Recognizer should be set to disabled. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
	}
}