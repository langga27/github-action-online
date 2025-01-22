package rules

detect_cmek_gcpbqr11(resource) {
	resource.default_encryption_configuration == []
}

deny[msg] {
	resource := input.resource.google_bigquery_dataset[name]
	detect_cmek_gcpbqr11(resource)

	msg := {
		# Mandatory fields
		"publicId": "GCPBQR11",
		"title": "GCPBQR11: Encryption at Rest (Dataset)",
		"severity": "high",
		# Use placeholders directly without variables
		"msg": sprintf("input.resource.google_bigquery_dataset[%s]", [name]),
		# Optional fields
		"issue": "Prudential managed key (CMEK) must be used to wraps the Google KEK for Cloud BigQuery encryption, for all created datasets",
		"impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the Google's encryption key and the encrypted data.",
		"remediation": "Please enable CMEK. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}