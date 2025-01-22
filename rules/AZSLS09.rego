package rules

deny[msg] {
  resource := input.resource.azurerm_mssql_server[name]
  not resource.connection_policy == "Default"

  msg := {
    # Mandatory fields
    "publicId": "AZSLS09",
    "title": "AZSLS09: Connection policy",
    "severity": "high",
    "msg": sprintf("input.resource.azurerm_mssql_server[%s]", [name]),
    # Optional fields
    "issue": "AZSLS09: Connection Policy must be set to default",
    "impact": "If the connection_policy is not set to 'Default', it could lead to potential connectivity issues, increased latency, or decreased performance.",
    "remediation": "Please set connection policy as default. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
    "references": ["https://code.pruconnect.net/projects/RTSRETM/repos/sql-managed-instance"],
  }
}