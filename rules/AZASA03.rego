package rules

exception_AZASA03(resource) {
	not startswith(resource.name, "f")
	not startswith(resource.name, "bootdiag")
	not startswith(resource.name, "nprdcoretools")
	not startswith(resource.name, "prodcoretools")
	not startswith(resource.name, "vmdiag")
	not resource.tags.ApplicationName == "hcf"
	not resource.tags.application == "databricks"
}

deny[msg] {
	resource := input.resource.azurerm_storage_account[name]
	not input.resource.azurerm_storage_account_customer_managed_key
	exception_AZASA03(resource)

	msg := {
		"publicId": "AZASA03",
		"title": "AZASA03: Encryption at Rest (CMEK) is not enabled",
		"severity": "high",
		"msg": sprintf("resource.azurerm_storage_account[%s]", [name]),
		"path": "resource > resource.azurerm_storage_account",
		"issue": "Encryption At Rest - When Azure Blob, File, Queue Storage and Tables are created, encryption must be configured to use Customer Managed Keys (CMEK).",
		"impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the microsoft encryption key and the encrypted data.",
		"remediation": "Please enable CMEK when provisioning the storage account. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details"
	}
}