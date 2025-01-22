package rules

deny[msg] {
    resource := input.resource.azurerm_eventhub_namespace[name]
    not input.resource.azurerm_eventhub_namespace_customer_managed_key

    msg := {
        # Mandatory Fields
        "publicId": "AZEVH11",
        "title": "AZEVH11: Encryption at Rest (CMEK) is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_eventhub_namespace[%s]", [name]),
        # Optional Fields
        "issue": "Azure Event Hub must be configured to use Customer Managed Keys (CMEK).",
        "impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the microsoft encryption key and the encrypted data.",
        "remediation": "Please enable CMEK when provisioning Azure Event Hub. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}
