package rules

deny[msg] {
    resource := input.resource.azurerm_redis_cache[name]
    resource.public_network_access_enabled
    not input.resource.azurerm_redis_firewall_rule

    msg := {
        # Mandatory fields
        "publicId": "AZRDC04",
        "title": "AZRDC04: Network Access Control is not restricted",
        "severity": "high",
        "msg": sprintf("resource.azurerm_redis_cache[%s]", [name]),
        # Optional fields
        "issue": "Azure Cache for Redis Premium must be configured with Virtual Network with firewall rules, or private endpoints.",
        "impact": "Azure Redis that are publically accessible may lead to unauthorized access by malicious user.",
        "remediation": "Azure Redis must be deployed within a virtual network, or firewall IP rules are configured. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": ""
    }
}