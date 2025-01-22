package rules

deny[msg] {
    resource := input.resource.azurerm_firewall_application_rule_collection[name]
    rules := resource.rule[_]
    rules.protocol[_].type != "Http"
    rules.protocol[_].type != "Https"

    msg := {
        # Mandatory fields
        "publicId": "AZFWL05",
        "title": "AZFWL05: Network Rule Collection",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_firewall_application_rule_collection[%s]", [name]),
        # Optional fields
        "path": "resource > resource.azurerm_firewall_application_rule_collection",
        "issue": "Only HTTP/HTTPS protocols are allowed.",
        "impact": "Only HTTP/HTTPS protocols are allowed for firewall application rule collection.",
        "remediation": "Please only set HTTP or HTTPS protocol for firewall application rule collection. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}
