package rules

msr_redis_instance_cmek_gcpmsr05(resource){
	resource.customer_managed_key == null
}

deny[msg] {
	resource := input.resource.google_redis_instance[name]
    msr_redis_instance_cmek_gcpmsr05(resource)
    

	msg := {
		# Mandatory fields
		"publicId": "GCPMSR05",
		"title": "GCPMSR05: Encryption at Rest",
		"severity": "high",
		"msg": sprintf("resource.google_redis_instance[%s]", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "Prudential managed key (CMEK) must be used to wraps the Google KEK for Memorystore for Redis encryption",
		"impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the Google's encryption key and the encrypted data.",
		"remediation": "Please enable CMEK. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}