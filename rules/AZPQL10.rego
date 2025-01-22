package rules

# module by default will add logging configuration

check_log_config(resource) {
	config := resource.azurerm_postgresql_configuration[_]
	not config.log_checkpoints
}

deny[msg] {
	resource := input.resource.azurerm_postgresql_server[name]
	check_log_config(resource)

	msg := {
		"publicId": "AZPQL10",
		"title": "AZPQL10: Logging within Server Parameter is not configured",
		"severity": "high",
		"msg": sprintf("input.resource.azurerm_postgresql_server[%s]", [name]),
		"issue": "AZPQL10: Server Parameter - Logging options per specified in the Standard should be configured accordingly.",
		"impact": "Logs are required for security investigation, in the event of a security incident",
        "remediation": "Please enable Logging options. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
		"references": ["https://code.pruconnect.net/projects/RTSRETM/repos/azure-postgresql-flexible/"],
	}
}
