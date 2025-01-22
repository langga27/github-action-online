package rules

detect_http_https_azfrd04(resource) {
	resource.is_http_allowed == true
}

detect_http_https_azfrd04(resource) {
	resource.is_https_allowed == false
}

deny[msg] {
    resource := input.resource.azurerm_cdn_endpoint[name]
    detect_http_https_azfrd04(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZFRD04",
        "title": "AZFRD04: Only HTTPS Protocol must be allowed for Routing Rules",
        "severity": "high",
        "msg": sprintf("resource.azurerm_cdn_endpoint[%s]", [name]),
        # Optional fields
        "issue": "Only HTTPS protocol must be allowed for a routing rule",
        "impact": "It is required to enable encyrption in transit to mitigate the risk of man in the middle threat",
        "remediation": "Please ensure only https routing is enabled. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": ""
    }
}