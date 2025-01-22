package rules

deny[msg] {
	resource := input.resource.azurerm_sql_managed_instance[name]
	resource.subnet_id == null

	msg := {
		# Mandatory fields
		"publicId": "AZSMI10",
		"title": "AZSMI10: Network Access Control",
		"severity": "high",
		"msg": sprintf("resource.azurerm_sql_managed_instance[%s]", [name]),
		"issue": "Azure SQL Managed Instance must be configured with Virtual network or private endpoint.",
		"impact": "Azure SQL Managed Instance must be configured with Virtual network or private endpoint.",
        "remediation": "Please configure Virtual network or private endpoint in the Azure SQL Managed Instance. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details"
	}
}