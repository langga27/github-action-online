package rules
import future.keywords.in

authSettingsCheck(resource) {
    some unauthClientAction in resource.auth_settings
    unauthClientAction.unauthenticated_client_action == "AllowAnonymous"
}

deny[msg] {
    resource := input.resource.azurerm_linux_web_app[name]
    authSettingsCheck(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZASV08LINUXWEBAPP",
        "title": "AZASV08: Anonymous Access is enabled",
        "severity": "high",
        "msg": sprintf("resource.azurerm_linux_web_app[%s]", [name]),
        # Optional fields
        "path": "resource > resource.azurerm_linux_web_app",
        "issue": "AZASV08: Anonymous access must be disabled ",
        "impact": "Unauthorized user may access application if anonymous access is enabled.",
        "remediation": "Please disable Anonymous access. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/azure-app-service/"
    }
}