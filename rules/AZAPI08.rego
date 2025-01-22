package rules

deny[msg] {
    resource := input.resource.azurerm_api_management[name]
    resource.tenant_access[_].enabled == true

    msg := {
        # Mandatory fields
        "publicId": "AZAPI08",
        "title": "AZAPI08: Azure API Management REST API is enabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_api_management[%s]", [name]),
        # Optional Fields
        "path": "resource > resource.azurerm_api_management",
        "issue": "Azure API Management REST API must be disabled.",
        "impact": "It is required to disable API Management REST API. Enabling of API Mangement REST API increase exposure and may lead to compromise of the API Management instance.",
        "remediation": "Please disable API Management REST API. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM"
    }
}