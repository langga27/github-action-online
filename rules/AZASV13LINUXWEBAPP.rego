package rules

remoteDebuggingCheck(resource) {
    remoteDebugging := resource.site_config[_]
    not remoteDebugging.remote_debugging_enabled == false
}

deny[msg] {
    resource := input.resource.azurerm_linux_web_app[name]
    remoteDebuggingCheck(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZASV13LINUXWEBAPP",
        "title": "AZASV13: Remote Debugging must be disabled",
        "severity": "high",
        "msg": sprintf("resource.azurerm_linux_web_app[%s]", [name]),
        # Optional fields
        "path": "resource > resource.azurerm_linux_web_app",
        "issue": "Remote Debugging must be disabled",
        "impact": "The remote debugging must be turned off as these ports become easy targets for compromise from various internet based attacks.",
        "remediation": "Please disable remote debugging. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
        "references": "https://code.pruconnect.net/projects/RTSRETM"
    }
}