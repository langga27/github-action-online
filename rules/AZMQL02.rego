package rules

deny[msg] {
	resource := input.resource.azurerm_mysql_server[name]
	not input.resource.azurerm_monitor_diagnostic_setting

	msg := {
		# Mandatory fields
		"publicId": "AZMQL02",
		"title": "AZMQL02: Diagnostic setting is not configured",
		"severity": "high",
		"msg": sprintf("input.resource.azurerm_mysql_server[%s]", [name]),
		# Optional fields
		"issue": "Diagnostics logs must be enabled to forward to Log Analytics Workspace for ingestion into Splunk.",
		"impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
		"remediation": "Please enable Diagnostic settings when provisioning the MySQL. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
		"references": ["https://code.pruconnect.net/projects/RTSRETM/repos/azure-mysql-flexible"],
	}
}
