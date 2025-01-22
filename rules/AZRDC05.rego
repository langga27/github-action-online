package rules

#For logic OR
tls_ssl_azrdc06(resource) {
    not resource.enable_non_ssl_port == false
}

tls_ssl_azrdc06(resource) {
    not resource.minimum_tls_version >= "1.2"
}

deny[msg] {
    resource := input.resource.azurerm_redis_cache[name]
    tls_ssl_azrdc06(resource)

    msg := {
        # Mandatory fields
        "publicId": "AZRDC05",
        "title": "AZRDC05: TLS version 1.2 is not configured",
        "severity": "high",
        "msg": sprintf("resource.azurerm_redis_cache[%s]", [name]),
        # Optional fields
        "issue": "Only connections via SSL to Azure Cache for Redis is allowed to ensure authentication between the server and the service, non-SSL port must be disabled and TLS1.2 must be used",
        "impact": "It is required to enable encryption in transit to mitigate the risk of man in the middle threat",
        "remediation": "Please ensure non ssl port is disabled and tls version 1.2 is used. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": ""
    }
}