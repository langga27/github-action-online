package rules
import future.keywords.in

check_AZFUN15LINUX(resource) {
    some siteConfig in resource.site_config
    siteConfig.ip_restriction == []
    resource.public_network_access_enabled != false
}

check_AZFUN15LINUX(resource) {
    some siteConfig in resource.site_config
    siteConfig.scm_ip_restriction == []
    resource.public_network_access_enabled != false
}

deny[msg] {
    resource := input.resource.azurerm_linux_function_app[name]
    check_AZFUN15LINUX(resource)

    msg := {
        # Mandatory Fields
        "publicId": "AZFUN15LINUX",
        "title": "AZFUN15: Azure Function must have IP restriction in place if is public facing.",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_linux_function_app[%s]", [name]),
        # Optional Fields
        "issue": "Azure Function must have IP restriction in place.",
        "impact": "Exposed Azure Function without any IP restriction may allow malicious user to have unauthorise access to azure function.",
        "remediation": "Please ensure IP addresses has been added into IP Restriction and SCM IP Restriction. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}