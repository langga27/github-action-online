#resource_changes[0].change.after.backend_http_settings[0].name

package rules

path_locator_azgat04_http(resource) {
    backendHttpSettings := resource.backend_http_settings[_]
    not backendHttpSettings.name == "be-http-default-80"
    backendHttpSettings.port == 80
    backendHttpSettings.protocol == "Http"
}

path_locator_azgat04_https(resource) {
    backendHttpSettings := resource.backend_http_settings[_]
    not backendHttpSettings.port == 443
    not backendHttpSettings.protocol == "Https"
}

deny[msg] {
    resource := input.resource.azurerm_application_gateway[name]
    path_locator_azgat04_http(resource)
    path_locator_azgat04_https(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZGAT04",
        "title": "AZGAT04: HTTPS protocol must be enabled",
        "severity": "high",
        "msg": sprintf("resource.azurerm_application_gateway[%s]", [name]),
        # Optional fields
        "issue": "AZGAT04: HTTPS protocol is to be enabled",
        "impact": "It is required to enable encyrption in transit to mitigate the risk of man in the middle threat",
        "remediation": "Please use Https only. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": ""
    }
}