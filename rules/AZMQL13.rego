package rules

deny[msg] {
   	input.resource.azurerm_mysql_server[name]
	not input.resource.azurerm_mysql_server_key

    msg := {
		# Mandatory fields
		"publicId": "AZMQL13",
		"title": "AZMQL13: Encryption at rest (CMEK) is not configured",
		"severity": "high",
		"msg": sprintf("input.resource.azurerm_mysql_server_key[%s]", [name]),
		# Optional fields
		"issue": "CMEK is not enabled when provisioning database.",
		"impact": "Without CMEK, malicious user is able to read the data if Microsoft managed Keys are compromised.",
		"remediation": "Please enable CMEK when provisioning database. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
		"references": ["https://code.pruconnect.net/projects/RTSRETM/repos/azure-mysql-flexible/browse"],        
    }
}
