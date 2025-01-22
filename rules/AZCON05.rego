package rules

deny[msg] {
    resource := input.resource.azurerm_app_configuration[name]
    resource.public_network_access == "Enabled"

    msg := {
        # Mandatory Fields
        "publicId": "AZCON05",
        "title": "AZCON05: Public Access is Enabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_app_configuration[%s]", [name]),
        # Optional Fields
        "issue": "All Azure App Configuration that are provisioned must have Public network access disabled",
        "impact": "Publically accessible Azure App Configuration may lead to unauthorized access by malicious users.",
        "remediation": "Please disable public network access of Azure App Configuration. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}