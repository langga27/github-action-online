package rules

webSocketCheck(resource) {
    azasv14WindowSiteConfig := resource.site_config[_]
    not azasv14WindowSiteConfig.websockets_enabled == false
}

deny[msg] {
    resource := input.resource.azurerm_windows_web_app[name]
    webSocketCheck(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZASV14WINDOWSWEBAPP",
        "title": "AZASV14: Web socket must be disabled",
        "severity": "high",
        "msg": sprintf("resource.azurerm_windows_web_app[%s]", [name]),
        # Optional fields
        "path": "resource > resource.azurerm_windows_web_app",
        "issue": "Web socket must be disabled",
        "impact": "Exposed web socket increases the surface of attack for malicious user.",
        "remediation": "Please disable web socket. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
        "references": "https://code.pruconnect.net/projects/RTSRETM"
    }
}