package rules

deny [msg] {
    resource := input.resource.azurerm_application_gateway[name]
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        "publicId": "AZGAT02",
        "title": "AZGAT02 Diagnostic setting is not configured",
        "severity": "high",
        "msg": sprintf("resource.azurerm_application_gateway[%s]", [name]),

        "issue": "AZGAT02: All Azure API Management instances that are provisioned must have loggin of ApplicationGatewayAccessLog",
        "impact": "Logs are required for security investigation, in the event of a security incident",
        "remediation": "Please enable Logging options when provisioning the AppGW. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/azure-monitor-diagnostic/browse"
    }
}
