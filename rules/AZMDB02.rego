package rules

deny[msg] {
	resource := input.resource.azurerm_mariadb_configuration[name]
    not input.resource.azurerm_monitor_diagnostic_setting

	msg := {
		# Mandatory fields
		"publicId": "AZMDB02",
		"title": "AZMDB02: Diagnostic setting is not configured",
		"severity": "high",
		"msg": sprintf("resource.azurerm_mariadb_configuration[%s]", [name]),
		"issue": "Diagnostics logs must be enabled to forward to Log Analytics Workspace for ingestion into Splunk.",
		"impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning Azure MariaDB. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
		"references": [""],
	}
}