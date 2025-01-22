package rules

check_logs(resource) {
	logs := input.resource.azurerm_mssql_server_extended_auditing_policy[name]
	not logs
}

deny[msg] {
    resource := input.resource.azurerm_mssql_server[name]
    check_logs(resource)

    msg := {
        "publicId": "AZSLS02",
        "title": "AZSLS02: Logging options must be enabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_mssql_server[%s]", [name]),

        "issue": "AZSLS02: All Azure SQL servers must have audit logs turned on",
        "impact": "Logs are required for security investigation, in the event of a security incident",
        "remediation": "Please enable Logging options. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/mssql/browse"
    }
}