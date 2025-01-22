package rules

deny[msg] {
	resource := input.resource.azurerm_cognitive_account[name]
	resource.kind == "OpenAI"
    not input.resource.azurerm_monitor_diagnostic_setting

	msg := {
		# Mandatory fields
		"publicId": "AZOAI02",
		"title": "AZOAI02: Diagnostic setting is not configured",
		"severity": "high",
		"msg": sprintf("resource.azurerm_cognitive_account[%s]", [name]),
		"issue": "All Azure OpenAI that are provisioned must have logging enabled and configured to send to Log Analytics Workspace which is integrated with Splunk.",
		"impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning Azure OpenAI. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
	}
}