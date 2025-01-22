package rules

deny [msg] {
	resource := input.resource.azurerm_mysql_server[name]
    not input.resource.azurerm_monitor_diagnostic_setting

    msg := {
        "publicId": "AZMQL03",
        "title": "AZMQL03: Audit Logs within Server Parameters must be enabled",
        "severity": "high",
        "msg": sprintf("resource.azurerm_mysql_server[%s]", [name]),
        "path": "resource > resource.azurerm_mysql_server",
        "issue": "Logging options of ADMIN, CONNECTION, DCL and DDL must be enabled.",
        "impact": "Logs are required for security investigation, in the event of a security incident",
        "remediation": "Please enable Logging options when provisioning the MySQL. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/azure-monitor-diagnostic/browse"
    }
}
