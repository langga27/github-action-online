package rules

deny[msg] {
    resource := input.resource.azurerm_firewall[name]
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        # Mandatory fields
        "publicId": "AZFWL03",
        "title": "AZFWL03: Diagnostic setting is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_firewall[%s]", [name]),
        # Optional fields
        "path": "resource > resource.azurerm_firewall",
        "issue": "Diagnostics logs must be enabled to forward to Log Analytics Workspace for ingestion into Splunk.",
        "impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic settings when provisioning the Azure Firewall. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/azure-firewall-rules/browse"
    }
}
