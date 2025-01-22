package rules

ipCheck(resource) {
    site_config := resource.site_config[_]
    site_config.ip_restriction == []
    site_config.scm_ip_restriction == []
}

deny[msg] {
    resource := input.resource.azurerm_app_service[name]
    ipCheck(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZASV12",
        "title": "AZASV12: IP Resriction and SCM IP Restriction are not configured",
        "severity": "high",
        "msg": sprintf("resource.azurerm_app_service[%s]", [name]),
        # Optional fields
        "path": "resource > resource.azurerm_app_service",
        "issue": "Access Restriction must be implemented to App Services Default Public URLs",
        "impact": "IP Restriction and SCM IP Restriction must be set to restrict access to Default Public URLs.",
        "remediation": "Please ensure IP addresses has been added into IP Restriction and SCM IP Restriction. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
        "references": "https://code.pruconnect.net/projects/RTSRETM"        
    }
}