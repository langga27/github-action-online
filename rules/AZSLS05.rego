package rules

disable_public_access(resource) {
    resource.public_network_access_enabled == true
}

deny[msg] {
    resource := input.resource.azurerm_mssql_server[name]
    disable_public_access(resource)
    not input.resource.azurerm_sql_firewall_rule
    
# This will deny if an MSSQL server is made without firewall or virtual network rule
# This include for sql firewall/vnr and mssql firewall/vnr


    msg := {
        "publicId": "AZSLS05",
        "title": "AZSLS05: Network access control must be restricted",
        "severity": "high",
        "msg": sprintf("resource.azurerm_sql_server[%s]", [name]),

        "issue": "Public network access must be disabled unless firewall rules or virtual network rules are configured.",
        "impact": "A database that is publically accessible may have the risk of unauthorised access by malicious user.",
        "remediation": "Please deploy database within a virtual network or configure firewall IP whitelsting when provisioning the database. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": ""
    }
}