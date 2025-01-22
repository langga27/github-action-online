package rules

deny[msg] {
	resource := input.resource.azurerm_servicebus_namespace[name]
    not resource.minimum_tl_version == "1.2"

	msg := {
		# Mandatory fields
		"publicId": "AZSVB06",
		"title": "AZSVB06: TLS version 1.2 is not configured",
		"severity": "high",
		"msg": sprintf("resource.azurerm_servicebus_namespace[%s]", [name]),
		"issue": "Azure Service Bus must use minimally TLS version 1.2 or above.",
		"impact": "Versions lower then TLS 1.2 is susceptible to attack by malicious user.",
        "remediation": "Please only use TLS 1.2 when provisioning the resource. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details"
	}
}