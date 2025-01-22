package rules

deny[msg] {
	resource := input.resource.azurerm_data_factory[name]
    resource.customer_managed_key_id == null

	msg := {
		# Mandatory fields
		"publicId": "AZFAC03",
		"title": "AZFAC03: Encryption at Rest (CMEK) is not configured",
		"severity": "high",
		"msg": sprintf("resource.azurerm_data_factory[%s]", [name]),
		"issue": "Azure Data Factory must be configured to use Customer Managed Keys (CMEK).",
		"impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the microsoft encryption key and the encrypted data.",
        "remediation": "Please enable CMEK when provisioning Azure Data Factory. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details."
	}
}