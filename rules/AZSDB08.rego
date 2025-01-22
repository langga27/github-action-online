package rules

#Disable for now as the GT's terraform module uses "null_resource" to enable TDE

deny[msg] {
    resource := input.resource.azurerm_mssql_database[name]
    not resource.transparent_data_encryption_enabled == true
    resource.transparent_data_encryption_enabled == true

    msg := {
        "publicId": "AZSDB08",
        "title": "AZSDB08: Transparent Data Encryption must be enabled",
        "severity": "high",
        "msg": sprintf("resource.azurerm_mssql_database[%s]", [name]),
        "path": "resource > resource.azurerm_mssql_database",
        "issue": "AZSDB08: Transparent Data Encryption must be enabled for all SQL Database instances.",
        "impact": "Without Transparent Data Encryption (TDE), the database does not have the database level encryption, and it is susceptible to attack by malicious user.",
        "remediation": "Please enable TDE when provisioning the database. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/sql-managed-instance/browse"
    }
}