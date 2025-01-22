package rules

# This rego could not handle two azurerm_mssql_database resource yet
# More advance logic will be made in the next action plan

deny[msg] {
    resource := input.resource.azurerm_mssql_database[name]
    not input.resource.azurerm_mssql_database_extended_auditing_policy
    input.resource.azurerm_mssql_database_extended_auditing_policy

    msg := {
        "publicId": "AZSDB02",
        "title": "AZSDB02: Logging options must be enabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_mssql_database[%s]", [name]),

        "issue": "AZSDB02: All Azure SQL Database instances that are provisioned must have Audit log turned on and configured to send to the Tenant Log Analytics Workspace which is integrated with Splunk",
        "impact": "Logs are required for security investigation, in the event of a security incident",
        "remediation": "Please enable Logging options. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/mssql/browse"
    }
}