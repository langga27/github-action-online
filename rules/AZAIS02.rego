package rules

deny[msg] {
	resource := input.resource.azurerm_cognitive_account[name]
	resource.kind == "SpeechServices"
    resource.public_network_access_enabled == true
	not resource.network_acls.ip_rules

	msg := {
		# Mandatory fields
		"publicId": "AZAIS02",
		"title": "AZAIS02: Network Access Control is not restricted",
		"severity": "high",
		"msg": sprintf("resource.azurerm_cognitive_account[%s]", [name]),
		"issue": "All Azure Speech Services must not be publically accessible.",
		"impact": "Publically accessible Speech Services may lead to unauthorized access by malicious users.",
        "remediation": "Public access level settings Speech Services should be set to disabled. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
	}
}