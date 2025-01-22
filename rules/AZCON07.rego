package rules

deny[msg] {
    resource := input.resource.azurerm_app_configuration[name]
    resource.encryption == []

    msg := {
        # Mandatory fields
        "publicId": "AZCON07",
        "title": "AZCON07: Encryption at Rest (CMEK) is not configured",
        "severity": "high",
        "msg": sprintf("resource.azurerm_app_configuration[%s]", [name]),
        # Optional fields
        "path": "resource > resource.azurerm_app_configuration",
        "issue": "Azure App Configuration must be configured to utilized customer-managed key encryption.",
        "impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the microsoft encryption key and the encrypted data.",
        "remediation": "Please enable CMEK when provisioning the resource. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
        "references": "https://code.pruconnect.net/projects/RTSRETM" 
    }
}