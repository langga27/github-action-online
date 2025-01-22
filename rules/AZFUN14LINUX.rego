package rules

deny[msg] {
    resource := input.resource.azurerm_linux_function_app[name]
    resource.site_config[_].websockets_enabled != false

    msg := {
        # Mandatory Fields
        "publicId": "AZFUN14LINUX",
        "title": "AZFUN14: Web socket must be disabled.",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_linux_function_app[%s]", [name]),
        # Optional Fields
        "issue": "Web socket must be disabled.",
        "impact": "Exposed web socket increases the surface of attack for malicious user.",
        "remediation": "Azure Function must have have web socket disabled. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}