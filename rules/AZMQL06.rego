package rules

deny[msg] { 
	resource := input.resource.azurerm_mysql_server[name] 
	public_access(resource)
    not input.resource.azurerm_mysql_firewall_rule

    msg := {
        "publicId": "AZMQL06",
        "title": "AZMQL06: Network access control must be restricted",
        "severity": "high",
        "msg": sprintf("resource.resource.azurerm_mysql_server[%s]", [name]),
        "path": "resource > resource.azurerm_mysql_server",
        "issue": "Public network access must be disabled unless firewall rules or virtual network rules are configured.",
        "impact": "A database that is publically accessible may have the risk of unauthorised access by malicious user.",
        "remediation": "Please deploy MySQL within a vertual network or configure firewall IP whitelsting when provisioning the MySQL. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/azure-mysql-flexible/browse"
    }
}

public_access(resource) {
	resource.public_network_access_enabled != false
}