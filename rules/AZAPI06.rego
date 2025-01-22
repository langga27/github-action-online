package rules

protocolCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.enable_backend_ssl30 == true
}

protocolCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.enable_backend_tls10 == true
}

protocolCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.enable_backend_tls11 == true
}

protocolCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.enable_frontend_ssl30 == true
}

protocolCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.enable_frontend_tls10 == true
}

protocolCheck(resource) {
    securityCheck := resource.security[_]
    securityCheck.enable_frontend_tls11 == true
}

protocolCheck(resource) {
    http2Check := resource.protocol[_]
    http2Check.enable_http2 == true
}

deny[msg] {
    resource := input.resource.azurerm_api_management[name]
    protocolCheck(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZAPI06",
        "title": "AZAPI06: Encryption in transit with TLS 1.2 is not enabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_api_management[%s]", [name]),
        # Optional Fields
        "path": "resource > resource.azurerm_api_management",
        "issue": "Only TLS 1.2 is allowed for both client-side transport security and backend-side transport security",
        "impact": "It is required to enable encyrption in transit with TLS 1.2 to mitigate the risk of man in the middle threats",
        "remediation": "Please ensure only TLS 1.2 is enabled. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM"
    }
}