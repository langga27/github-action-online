package rules    

deny[msg] {
    resource := input.resource.azurerm_mssql_server[name]
    not input.resource.azurerm_mssql_server_transparent_data_encryption
    input.resource.azurerm_mssql_server_transparent_data_encryption

    msg := {
        "publicId": "AZSLS12",
        "title": "AZSLS12: Transparent Data Encryption is not enabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_mssql_server[%s].", [name]),

        "issue": "AZSLS12: Transparent Data encryption must be enabled for all SQL Servers using Prudential managed key",
        "impact": "Without Transparent Data Encryption (TDE), the database does not have the database level encryption, and it is susceptible to attack by malicious user.",
        "remediation": "Please enable TDE when provisioning the database. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/mssql/browse"        
    }
}