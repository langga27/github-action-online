package rules

deny[msg] {
    resource := input.resource.azurerm_cosmosdb_account[name]
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        # Mandatory Fields
        "publicId": "AZCDB02",
        "title": "AZCDB02: Diagnostic setting is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_cosmosdb_account[%s]", [name]),
        # Optional Fields
        "issue": "Diagnostics logs must be enabled to forward to Log Analytics Workspace for ingestion into Splunk.",
        "impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic logging when provisioning Azure CosmosDB. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}