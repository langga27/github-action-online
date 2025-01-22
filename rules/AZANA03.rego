package rules

deny[msg] {
    resource := input.resource.azurerm_analysis_services_server[name]
    not resource.ipv4_firewall_rule

    msg := {
        # Mandatory Fields
        "publicId": "AZANA03",
        "title": "AZANA02: Firewall rule is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_analysis_services_server[%s]", [name]),
        # Optional Fields
        "issue": "All Azure Analysis Service that are provisioned must have firewall rules set to explicitly allow specific source IP to access.",
        "impact": "Azure Analysis Services that are publically accessible may lead to unauthorized access by malicious user.",
        "remediation": "Please deploy Azure Analysis Service with firewall rules. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}