package rules

deny[msg] {
    resource := input.resource.azurerm_automation_account[name]
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        # Mandatory Fields
        "publicId": "AZAUT03",
        "title": "AZAUT03: Diagnostic setting is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_automation_account[%s]", [name]),
        # Optional Fields
        "issue": "All Azure automation account that are provisioned must have logging enabled and configured to send to Log Analytics Workspace which is integrated with Splunk.",
        "impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning Azure automation account. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}
