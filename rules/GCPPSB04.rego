package rules

detect_cmek_gcppsb04(resource) {
	resource.kms_key_name == null
}

deny[msg] {
	resource := input.resource.google_pubsub_topic[name]
	detect_cmek_gcppsb04(resource)

	msg := {
		# Mandatory fields
		"publicId": "GCPPSB04",
		"title": "GCPPSB04: Encryption at Rest",
		"severity": "high",
		# Use placeholders directly without variables
		"msg": sprintf("input.resource.google_pubsub_topic[%s]", [name]),
		# Optional fields
		"issue": "Prudential managed key (CMEK) must be used to wraps the Google KEK for Cloud Pub Sub encryption, for all created topics",
		"impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the Google's encryption key and the encrypted data.",
		"remediation": "Please enable CMEK. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}