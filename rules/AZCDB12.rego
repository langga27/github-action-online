package rules

deny[msg] {
    resource := input.resource.azurerm_cosmosdb_account[name]
    resource.key_vault_key_id == ""

    msg := {
        # Mandatory Fields
        "publicId": "AZCDB12",
        "title": "AZCDB12: Encryption at Rest (CMEK) is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_cosmosdb_account[%s]", [name]),
        # Optional Fields
        "issue": "Azure Cosmos DB must be configured to use Customer Managed Keys (CMEK)",
        "impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the microsoft encryption key and the encrypted data.",
        "remediation": "Please enable CMEK when provisioning Azure Cosmos DB. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}