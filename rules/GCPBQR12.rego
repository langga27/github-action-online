package rules

detect_cmek_gcpbqr12(resource) {
	not resource.encryption_configuration
}

deny[msg] {
	resource := input.resource.google_bigquery_table[name]
	detect_cmek_gcpbqr12(resource)

	msg := {
		# Mandatory fields
		"publicId": "GCPBQR12",
		"title": "GCPBQR12: Encryption at Rest (Table)",
		"severity": "high",
		# Use placeholders directly without variables
		"msg": sprintf("input.resource.google_bigquery_table[%s]", [name]),
		# Optional fields
		"issue": "GCPBQR12: Prudential managed key (CMEK) must be used to wraps the Google KEK for Cloud BigQuery encryption, for all created tables",
		"impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the Google's encryption key and the encrypted data.",
		"remediation": "Please enable CMEK. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}