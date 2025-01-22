package rules

deny[msg] {
    resource := input.resource.azurerm_linux_function_app[name]
    resource.site_config[_].ftps_state != "Disabled"

    msg := {
        # Mandatory Fields
        "publicId": "AZFUN06LINUX",
        "title": "AZFUN06: FTP based Deployment must be Disabled.",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_linux_function_app[%s]", [name]),
        # Optional Fields
        "issue": "All Azure Functions that are provisioned must have FTP based deployment Disabled.",
        "impact": "Deployment in Prudential is strictly only via CI/CD tool, as such FTP based deployment must be disabled.",
        "remediation": "FTP based deployment for Azure Functions must be set to disabled. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}