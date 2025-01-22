package rules

deny[msg] {
    resource := input.resource.azurerm_automation_account[name]
    resource.public_network_access_enabled != false

    msg := {
        # Mandatory Fields
        "publicId": "AZAUT10",
        "title": "AZAUT10: Public Network Access is enabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_automation_account[%s]", [name]),
        # Optional Fields
        "issue": "All Azure automation account that are provisioned must have public network access Disabled.",
        "impact": "Publically accessible Azure Automation may lead to unauthorized access by malicious users.",
        "remediation": "Public access level settings for Azure Automation should be set to disabled. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}