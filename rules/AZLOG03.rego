package rules

deny[msg] {
    resource := input.resource.azurerm_log_analytics_workspace[name]
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        # Mandatory Fields
        "publicId": "AZLOG03",
        "title": "AZLOG03: Diagnostic setting is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_log_analytics_workspace[%s]", [name]),
        # Optional Fields
        "issue": "All Azure Log Analytics that are provisioned must have logging enabled and configured to send to Log Analytics Workspace which is integrated with Splunk.",
        "impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning Azure Log Analytics. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}
