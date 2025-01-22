package rules

deny[msg] {
    resource := input.resource.azurerm_app_configuration[name]
    not resource.identity == "SystemAssigned"

    msg := {
        # Mandatory Fields
        "publicId": "AZCON04",
        "title": "AZCON04: System Assigned Managed Identity is not enabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_app_configuration[%s]", [name]),
        # Optional Fields
        "issue": "All Azure App Configuration that are provisioned must have System Assigned Managed Identity enabled",
        "impact": "Azure App Configuration should have System Asssigned Managed Identity enabled to allow other service to connect to.",
        "remediation": "Please enable System Assigned Managed Identity when provisioning Azure App Configuration. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
    }
}