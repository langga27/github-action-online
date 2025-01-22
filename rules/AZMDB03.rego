package rules

azure_mariadb_settings_AZMDB03(resource){
	resource.name == "audit_log_enabled"
    not resource.value == "ON"
}
azure_mariadb_settings_AZMDB03(resource){
	resource.name == "audit_log_events"
    not resource.value == "ADMIN,CONNECTION,DCL,DDL"
}


deny[msg] {
	resource := input.resource.azurerm_mariadb_configuration[name]
    azure_mariadb_settings_AZMDB03(resource)
	not azure_mariadb_settings_AZMDB03(resource)

	msg := {
		# Mandatory fields
		"publicId": "AZMDB03",
		"title": "AZMDB03: Audit Log within Server parameters must be enabled",
		"severity": "high",
		"msg": sprintf("resource.azurerm_mariadb_configuration[%s]", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "All Azure Database for MariaDB instances that are provisioned must have logging of MariaDB Audit Logs enabled with value of ADMIN,CONNECTION,DCL,DDL.",
		"impact": "This is to ensure sufficient logs are avaiable, in the event it is required for security investigation purpose.",
        "remediation": "Please enable audit logging with values of ADMIN,CONNECTION,DCL and DDL. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
		"references": [""],
	}
}