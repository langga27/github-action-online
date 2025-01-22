package rules

dataproc_enable_kerberos_check(resource){
	indexone := resource.cluster_config[_]
	indextwo := indexone.security_config[_]
	indexthree := indextwo.kerberos_config[_]
	indexthree.enable_kerberos == true
}

deny[msg] {
	resource := input.resource.google_dataproc_cluster[name]
    dataproc_enable_kerberos_check(resource)
    

	msg := {
		# Mandatory fields
		"publicId": "GCPPRC13",
		"title": "GCPPRC13: Metastore Kerberos Base Authentication",
		"severity": "high",
		"msg": sprintf("resource.google_dataproc_cluster[%s]", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "Kerberos based authentication is not allowed to be used in Prudential environment.",
		"impact": "Allowing Kerberos based authentication increases the risk and exposure of the resource.",
		"remediation": "Please disable kerberos authentication. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}