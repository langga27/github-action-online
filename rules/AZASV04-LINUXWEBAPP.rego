package rules

deny[msg] {
    resource := input.resource.azurerm_linux_web_app[name]
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        # Mandatory fields
        "publicId": "AZASV04-LINUXWEBAPP",
        "title": "AZASV04: Diagnostic setting is not enabled",
        "severity": "high",
        "msg": sprintf("resource.azurerm_linux_web_app[%s]", [name]),
        # Optional fields
        "issue": "All Azure App Service that are provisioned must have logging enabled and configured to send to Log Analytics Workspace which is integrated with Splunk.",
        "impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning Azure App Service. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": ""
    }
}