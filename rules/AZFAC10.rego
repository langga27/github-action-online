package rules

deny[msg] {
	resource := input.resource.azurerm_data_factory[name]
    resource.public_network_enabled == true

	msg := {
		# Mandatory fields
		"publicId": "AZFAC10",
		"title": "AZFAC10: Network Access Control is not restricted",
		"severity": "high",
		"msg": sprintf("resource.azurerm_data_factory[%s]", [name]),
		"issue": "Azure Data Factory must be configured with Virtual Network with firewall rules, or private endpoints.",
		"impact": "Azure Data Factory that are publically accessible may lead to unauthorized access by malicious user.",
        "remediation": "Azure Data Factory must be deployed within a virtual network, or firewall IP rules are configured. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
	}
}