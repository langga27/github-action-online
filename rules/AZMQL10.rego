package rules

import data.lib

ssl_tls_config(resource) {
    resource.ssl_enforcement_enabled != true
}

ssl_tls_config(resource) {
    resource.ssl_minimal_tls_version_enforced != "TLS1_2"
}


deny[msg] {
    resource := input.resource.azurerm_mysql_server[name]
    ssl_tls_config(resource)

    msg := {
        "publicId": "AZMQL10",
        "title": "AZMQL10: TLS version 1.2 is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_mysql_server[%s].ssl_minimal_tls_version_enforced", [name]),
        "path": "resource > resource.azurerm_mysql_server",
        "issue": "The minimum TLS version on the Azure Mysql must be set to version 1.2",
        "impact": "Versions lower then TLS 1.2 is susceptible to attack by malicious user.",
        "remediation": "Please use TLS 1.2 when provisioning the Azure Mysql. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details"
    }
}
