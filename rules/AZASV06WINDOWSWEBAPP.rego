package rules

ftpsCheck(resource) {
    ftps := resource.site_config[_]
    not ftps.ftps_state == "Disabled"
}

deny[msg] {
    resource := input.resource.azurerm_windows_web_app[name]
    ftpsCheck(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZASV06WINDOWSWEBAPP",
        "title": "AZASV06: FTP based Deployment must be Disabled",
        "severity": "high",
        "msg": sprintf("resource.azurerm_windows_web_app[%s]", [name]),
        # Optional fields
        "path": "resource > resource.azurerm_windows_web_app",
        "issue": "AZASV06: FTP based Deployment must be Disabled",
        "impact": "Deployment must be strictly through CI/CD tools with DevSecOps integration.",
        "remediation": "Please disable FTP based deployment. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
        "references": "https://code.pruconnect.net/projects/RTSRETM"
    }
}