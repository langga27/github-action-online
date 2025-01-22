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
	resource := input.resource.azurerm_storage_account_blob_container_sas[name]
	resource.https_only != true
	startswith_f(resource)
	startswith_bootdiag(resource)
	endswith_vmdiag(resource)
	applicationName_tags(resource)

	msg := {
		"publicId": "AZASA06",
		"title": "AZASA06: Allow HTTPS only for Shared Access Signature (SAS) is not enabled",
		"severity": "high",
		"msg": sprintf("resource.azurerm_storage_account_blob_container_sas[%s]", [name]),
		"path": "resource > resource.azurerm_storage_account_blob_container_sas",
		"issue": "SAS tokens must only be allowed to connect using HTTPS.",
		"impact": "without HTTPS, the storage account may be at risk to man-in-the-middle attack.",
		"remediation": "Please only enable HTTPS when provisioning the storage account blob container. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details",
		"references": "https://code.pruconnect.net/projects/RTSRETM/repos/storage-account/browse",
	}
}