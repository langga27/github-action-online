package rules

kms_key_name_check_GCPPRC14(resource){
    indexedone := resource.cluster_config[_]
    indexedtwo := indexedone.encryption_config[_]
	not indexedtwo.kms_key_name
}
kms_key_name_check_GCPPRC14(resource){
    indexedone := resource.cluster_config[_]
	not indexedone.encryption_config
}
kms_key_name_check_GCPPRC14(resource){
	not resource.cluster_config
}


deny[msg] {
	resource := input.resource.google_dataproc_cluster[name]
    kms_key_name_check_GCPPRC14(resource)

	msg := {
		# Mandatory fields
		"publicId": "GCPPRC14",
		"title": "GCPPRC14: Metastore Encryption at Rest",
		"severity": "high",
		"msg": sprintf("resource.google_dataproc_cluster[%s]", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "For Metastore, Prudential managed key (CMEK) must be used to wraps the Google KEK for Cloud Dataproc encryption",
		"impact": "This is to reduce the risk in the event encryption keys that are managed by Cloud Service Providers are compromised.",
		"remediation": "Please enable CMEK when using Metastore. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}