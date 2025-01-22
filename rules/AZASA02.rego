package rules

deny[msg] {
    resource := input.resource.azurerm_storage_account[name]
    not startswith(resource.name, "f")
    not startswith(resource.name, "bootdiag")
    not startswith(resource.name, "dbstorage")
    not endswith(resource.name, "vmdiag")
    not resource.tags.ApplicationName == "hcf"
    not resource.tags.application == "databricks"
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        "publicId": "AZASA02",
        "title": "AZASA02: Diagnostic setting is not configured",
        "severity": "high",
        "msg": sprintf("resource.azurerm_storage_account[%s]", [name]),
        "path": "resource > resource.azurerm_storage_account",
        "issue": "Diagnostics logs must be enabled to forward to Log Analytics Workspace for ingestion into Splunk.",
        "impact": "Diagnostic logs are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable Diagnostic settings when provisioning the storage account. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/storage-account/browse"
    }
}
