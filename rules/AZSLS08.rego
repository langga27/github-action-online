package rules

azurerm_mssql_server_outbound_restricted(resource) {
    not resource.outbound_network_restriction_enabled == true
}

deny[msg] {
    resource := input.resource.azurerm_mssql_server[name]
    azurerm_mssql_server_outbound_restricted(resource)
    not azurerm_mssql_server_outbound_restricted(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZSLS08",
        "title": "AZSLS08: Outbound Networking must be restricted",
        "severity": "high",
        "msg": sprintf("resource.azurerm_mssql_server[%s]", [name]),
        # Optional fields
        "path": "resource > resource.azurerm_mssql_server",
        "issue": "Outbound networking should be restricted.",
        "impact": "without restriction of outbound networking, there is a risk in data exfiltration.",
        "remediation": "Please ensure outbound networking restriction is defined. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/sql-managed-instance/browse"
    }
}