package rules

deny[msg] {
    resource := input.resource.azurerm_eventhub_namespace[name]
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        # Mandatory Fields
        "publicId": "AZEVH04",
        "title": "AZEVH04: Diagnostic setting is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_eventhub_namespace[%s]", [name]),
        # Optional Fields
        "issue": "All Azure Event Hub that are provisioned must have logging enabled and configured to send to Log Analytics Workspace which is integrated with Splunk.",
        "impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning Azure Event Hub. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}
