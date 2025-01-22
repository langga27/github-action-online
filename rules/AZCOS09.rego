package rules

deny[msg] {
	resource := input.resource.azurerm_cognitive_account[name]
	resource.kind == "CognitiveServices"
    resource.public_network_access_enabled == true
	not resource.network_acls.ip_rules

	msg := {
		# Mandatory fields
		"publicId": "AZCOS09",
		"title": "AZCOS09: Network Access Control is not restricted",
		"severity": "high",
		"msg": sprintf("resource.azurerm_cognitive_account[%s]", [name]),
		"issue": "Azure Cognitive Search must be configured with Virtual Network with firewall rules, or private endpoints.",
		"impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning Azure Cognitive Search. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
	}
}