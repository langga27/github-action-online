package rules

deny[msg] {
    resource := input.resource.azurerm_api_management[name]
    resource.virtual_network_configuration == []

    msg := {
        # Mandatory Fields
        "publicId": "AZAPI04",
        "title": "AZAPI04: Virtual Network is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_api_management[%s]", [name]),
        # Optional Fields
        "issue": "The API Management gateway and developer portal are accessible only from within the virtual network via an internal load balancer",
        "impact": "Resource must be within virtual network, and shall not be publically accessible. This is to reduce the risk on unauthorise access.",
        "remediation": "Please configure the resource with Virtual network. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM"
    }
}