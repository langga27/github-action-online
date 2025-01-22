package rules
import future.keywords.in

check_AZFRD03(resource) {
    some backendPoolHealthProbe in resource.backend_pool_health_probe
    backendPoolHealthProbe.protocol != "Https"
}

deny[msg] {
    resource := input.resource.azurerm_frontdoor[name]
    check_AZFRD03(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZFRD03",
        "title": "AZFRD03: Backend Pools Health Probes must only use HTTPS protocol",
        "severity": "high",
        "msg": sprintf("resource.azurerm_frontdoor[%s]", [name]),
        # Optional fields
        "issue": "Only HTTPS protocol can be used for communication to backend pools for health probes.",
        "impact": "It is required to enable encyrption in transit to mitigate the risk of man in the middle threat",
        "remediation": "Please ensure only https is enabled for communication to backend pools. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": ""
    }
}