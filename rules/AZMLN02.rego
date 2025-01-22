package rules

deny[msg] {
	resource := input.resource.azurerm_machine_learning_workspace[name]
    not input.resource.azurerm_monitor_diagnostic_setting

	msg := {
		# Mandatory fields
		"publicId": "AZMLN02",
		"title": "AZMLN02: Diagnostic setting is not configured",
		"severity": "high",
		"msg": sprintf("resource.azurerm_machine_learning_workspace[%s]", [name]),
		"issue": "All Azure Machine Learning that are provisioned must have logging enabled and configured to send to Log Analytics Workspace which is integrated with Splunk.",
		"impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning Azure Machine Learning. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
		"references": [""],
	}
}