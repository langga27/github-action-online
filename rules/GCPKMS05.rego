package rules

detect_kms_rotper_gcpkms05(resource) {
	period := trim_suffix(resource.rotation_period, "s")
    num := to_number(period)
    num >= 94608000
}

deny[msg] {
	resource := input.resource.google_kms_crypto_key[name]
    detect_kms_rotper_gcpkms05(resource)

	msg := {
		# Mandatory fields
		"publicId": "GCPKMS05",
		"title": "GCPKMS05: Key Rotation Period",
		"severity": "high",
		"msg": sprintf("resource.google_kms_crypto_key[%s]", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "All CMEK keys used in Prudential must be rotated within 3 years of validity",
		"impact": "Key rotation must be done within 3 years to reduce the risk of key exposure, as well as prevent malicious user from using the key to decrypt old data",
		"remediation": "Please set the key rotation to less than 3 years. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}