package rules

deny[msg] {
    resource := input.resource.azurerm_linux_web_app[name]
    resource.client_certificate_enabled != false

    msg := {
        # Mandatory Fields
        "publicId": "AZASV09LINUXWEBAPP",
        "title": "AZASV09: Incoming Client Certificates is not configured to be ignored",
        "severity": "high",
        "msg": sprintf("input.azurerm_app_service[%s]", [name]),
        # Optional Fields
        "issue": "All Azure App Service that are provisioned must have incoming client certificates set to Ignore",
        "impact": "Incoming client certificates must be set to Ignore as RBAC is used instead.",
        "remediation": "Please set incoming client certificates to Ignore. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}