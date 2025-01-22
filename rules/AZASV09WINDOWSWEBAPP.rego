package rules

deny[msg] {
    resource := input.resource.azurerm_windows_web_app[name]
    resource.client_certificate_enabled != false

    msg := {
        # Mandatory fields
        "publicId": "AZASV09WINDOWSWEBAPP",
        "title": "AZASV09: Incoming Client Certificates is not configured to be ignored",
        "severity": "high",
        "msg": sprintf("resource.azurerm_windows_web_app[%s]", [name]),
        # Optional fields
        "issue": "All Azure App Service that are provisioned must have incoming client certificates set to Ignore",
        "impact": "IP Restriction and SCM IP Restriction must be set to restrict access to Default Public URLs.",
        "remediation": "Please set incoming client certificates to Ignore. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}