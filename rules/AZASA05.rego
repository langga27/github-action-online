package rules

startswith_f(resource) {
	not startswith(resource.name, "f")
}

startswith_bootdiag(resource) {
	not startswith(resource.name, "bootdiag")
}

endswith_vmdiag(resource) {
	not endswith(resource.name, "vmdiag")
}

applicationName_tags(resource) {
	not resource.tags.ApplicationName == "hcf"
}

deny[msg] {
	resource := input.resource.azurerm_storage_account[name]
	resource.enable_https_traffic_only != true
	startswith_f(resource)
	startswith_bootdiag(resource)
	endswith_vmdiag(resource)
	applicationName_tags(resource)

	msg := {
		"publicId": "AZASA05",
		"title": "AZASA05: Secure transfer setting is not enabled",
		"severity": "high",
		"msg": sprintf("resource.azurerm_storage_account[%s]", [name]),
		"path": "resource > resource.azurerm_storage_account",
		"issue": "Secure Transfer Required must be set to ensure all connections to storage account is HTTPS.",
		"impact": "without HTTPS, the storage account may be at risk to man-in-the-middle attack.",
		"remediation": "Please Secure Transfer Required when provisioning the storage account. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
		"references": "https://code.pruconnect.net/projects/RTSRETM/repos/storage-account/browse",
	}
}