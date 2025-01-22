package rules

deny[msg] {
    resource := input.resource.azurerm_eventhub_namespace[name]
    not resource.min_tls_version == 1.2

    msg := {
        # Mandatory Fields
        "publicId": "AZEVH10",
        "title": "AZEVH10: TLS version 1.2 is not configured",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_eventhub_namespace[%s]", [name]),
        # Optional Fields
        "issue": "Azure Event Hub must be configured to use TLS version 1.2.",
        "impact": "It is required to enable encryption in transit to mitigate the risk of man in the middle threat.",
        "remediation": "Please ensure tls version 1.2 is used. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.."
    }
}
