package rules

deny[msg] {
    resource := input.resource.azurerm_linux_function_app[name]
    resource.client_certificate_enabled != false
    resource.client_certificate_mode != "Optional"

    msg := {
        # Mandatory Fields
        "publicId": "AZFUN09LINUX",
        "title": "AZFUN09: Incoming client certificates must be set to Optional.",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_linux_function_app[%s]", [name]),
        # Optional Fields
        "issue": "Incoming client certificates must be set to Optional as applications running in Azure Function relies on RBAC.",
        "impact": "Azure Function should relie on RBAC.",
        "remediation": "Azure Function must have set to Optional for incoming client certificates. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}