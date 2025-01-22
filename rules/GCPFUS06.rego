package rules

google_data_fusion_instance_cmek_check_GCPFUS06(resource){
	index := resource.crypto_key_config
	count(index) == 0
}


deny[msg] {
	resource := input.resource.google_data_fusion_instance[name]
    google_data_fusion_instance_cmek_check_GCPFUS06(resource)

	msg := {
		# Mandatory fields
		"publicId": "GCPFUS06",
		"title": "GCPFUS06: Encryption at Rest",
		"severity": "high",
		"msg": sprintf("resource.google_data_fusion_instance[%s]", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "Prudential managed key (CMEK) must be used to wraps the Google KEK for Cloud Data Fusion encryption.",
		"impact": "This is to reduce the risk in the event encryption keys that are managed by Cloud Service Providers are compromised.",
		"remediation": "Please enable CMEK. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}