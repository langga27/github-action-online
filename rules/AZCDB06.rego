package rules

deny[msg] {
    resource := input.resource.azurerm_cosmosdb_account[name]
    resource.public_network_access_enabled == true
    not resource.ip_range_filter

    msg := {
        # Mandatory Fields
        "publicId": "AZCDB06",
        "title": "AZCDB06: Network Access Control is not restricted",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_cosmosdb_account[%s]", [name]),
        # Optional Fields
        "issue": "Azure Cosmos DB must be configured with Virtual Network with firewall rules, or private endpoints.",
        "impact": "Azure Cosmos DB that are publically accessible may lead to unauthorized access by malicious user.",
        "remediation": "Azure Cosmos DB must be deployed within a virtual network, or firewall IP rules are configured. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}