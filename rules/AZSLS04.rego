package rules

firewall_or_vnet_detected_sqlmssql(resource) {

    not input.resource.azurerm_sql_firewall_rule
    not input.resource.azurerm_sql_virtual_network_rule
    not input.resource.azurerm_mssql_firewall_rule
    not input.resource.azurerm_mssql_virtual_network_rule
}

disable_public_access(resource) {
    resource.public_network_access_enabled == true
}

deny[msg] {
    resource := input.resource.azurerm_mssql_server[name]
    disable_public_access(resource)
    not disable_public_access(resource)
    firewall_or_vnet_detected_sqlmssql(resource)

    msg := {
      # Mandatory fields
      "publicId": "AZSLS04",
      "title": "AZSLS04: Network access control must be restricted",
      "severity": "high",
      "msg": sprintf("input.resource.azurerm_mssql_server[%s]", [name]),
      # Optional fields
      "issue": "Public network access must be disabled unless firewall rules or virtual network rules are configured.",
      "impact": "Please deploy database within a virtual network or configure firewall IP whitelsting when provisioning the database. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
      "references": [""],
    }
}