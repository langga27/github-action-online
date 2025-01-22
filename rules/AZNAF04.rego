package rules

deny[msg] {
	resource := input.resource.azurerm_netapp_volume[name]
	not resource.protocols == "NFSv4.1"

	msg := {
		# Mandatory fields
		"publicId": "AZNAF04",
		"title": "AZNAF04: NFSv4.1 protocol is not configured",
		"severity": "high",
		"msg": sprintf("resource.azurerm_netapp_volume[%s]", [name]),
		"issue": "All Azure Netapps File must use NFSv4.1 as the protocol.",
		"impact": "Usage of weak protocol may lead to unauthorised access to malicious user.",
        "remediation": "Please enable NFSv4.1 when provisioning Azure Netapp Files. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
		"references": [""],
	}
}