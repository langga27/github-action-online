package rules

deny[msg] {
	resource := input.resource.azurerm_sql_managed_instance[name]
	not input.resource.azurerm_mssql_managed_instance_transparent_data_encryption

	msg := {
		# Mandatory fields
		"publicId": "AZSMI14",
		"title": "AZSMI14: Transparent Data Encryption",
		"severity": "high",
		"msg": sprintf("resource.azurerm_sql_managed_instance[%s]", [name]),
		"issue": "Azure SQL Managed Instance must be configured with Transparent Data Encryption.",
		"impact": "Azure SQL Managed Instance must be configured with Transparent Data Encryption.",
        "remediation": "Please configure Transparent Data Encryption in the Azure SQL Managed Instance. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details"
	}
}