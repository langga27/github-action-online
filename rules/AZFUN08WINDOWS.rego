package rules

check_AZFUN08WINDOWS(resource) {
    resource.auth_settings[_].enabled == false
}

check_AZFUN08WINDOWS(resource) {
    resource.auth_settings[_].unauthenticated_client_action == "AllowAnonymous"
}

deny[msg] {
    resource := input.resource.azurerm_windows_function_app[name]
    check_AZFUN08WINDOWS(resource)

    msg := {
        # Mandatory Fields
        "publicId": "AZFUN08WINDOWS",
        "title": "AZFUN08: Restrict access must be set to Require Authentication and not allow anonymous access.",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_windows_function_app[%s]", [name]),
        # Optional Fields
        "issue": "All Azure Functions that are provisioned must have Restrict access set to Require Authentication and not allow anonymous access.",
        "impact": "Azure Function without restrict access may lead to malicious user accessing the azure funtion.",
        "remediation": "Azure Function must have restrict access set to require authentication. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}