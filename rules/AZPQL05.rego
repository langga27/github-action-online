package rules

deny[msg] {
    resource := input.resource.azurerm_postgresql_server[name]
    public_network_access(resource)
    not input.resource.azurerm_postgresql_firewall_rule

    msg := {
        "publicId": "AZPQL05",
        "title": "AZPQL05: Network access control is not restricted",
        "severity": "high",
        "msg": sprintf(" input.resource.azurerm_postgresql_server[%s]", [name]),
        "path": "resource > resource.azurerm_postgresql_server",
        "issue": "Public network access must be disabled unless firewall rules or virtual network rules are configured.",
        "impact": "A database that is publically accessible may have the risk of unauthorised access by malicious user.",
        "remediation": "Please deploy PosgreSQL within a virtual network or configure firewall IP whitelsting when provisioning the database. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/postgresql/browse"
    }
}

public_network_access(resource) {
    resource.public_network_access_enabled == true
}