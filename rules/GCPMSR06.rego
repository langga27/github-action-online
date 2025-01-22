package rules

deny[msg] {
	resource := input.resource.google_redis_instance[name]
    not resource.transit_encryption_mode == "SERVER_AUTHENTICATION"

	msg := {
		# Mandatory fields
		"publicId": "GCPMSR06",
		"title": "GCPMSR06: Encryption in Transit",
		"severity": "high",
		"msg": sprintf("resource.google_redis_instance[%s]", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "TLS encryption must be enabled for all Memorystore instances",
		"impact": "It is required to enable encyrption in transit to mitigate the risk of man in the middle threat",
		"remediation": "Please enable in-transit encryption. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}