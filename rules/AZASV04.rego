package rules

deny[msg] {
    resource := input.resource.azurerm_app_service[name]
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        # Mandatory Fields
        "publicId": "AZASV04",
        "title": "AZASV04: Diagnostic setting is not enabled",
        "severity": "high",
        "msg": sprintf("input.azurerm_app_service[%s]", [name]),
        # Optional Fields
        "issue": "All Azure App Service that are provisioned must have logging enabled and configured to send to Log Analytics Workspace which is integrated with Splunk.",
        "impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning Azure App Service. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}
