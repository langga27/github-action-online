package rules
import future.keywords.in

check_AZFRD06(resource) {
    some tls in resource.tls
    tls.minimum_tls_version != "TLS12"
}

deny[msg] {
    resource := input.resource.azurerm_cdn_frontdoor_custom_domain[name]
    check_AZFRD06(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZFRD06",
        "title": "AZFRD06: TLS version 1.2 is not configured",
        "severity": "high",
        "msg": sprintf("resource.azurerm_cdn_frontdoor_custom_domain[%s]", [name]),
        # Optional fields
        "issue": "Azure frontdoor custom domain must have minimally TLS 1.2 version.",
        "impact": "Versions lower then TLS 1.2 is susceptible to attack by malicious user.",
        "remediation": "Please ensure to use TLS 1.2for Azure Frontdoor custom domain. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": ""
    }
}