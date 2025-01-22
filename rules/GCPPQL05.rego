package rules

GCPPQL05_plsql_db_flag_check(resource){
	settings_index := resource.settings[_]
	flags_index := settings_index.database_flags[_]
	flags_index.name == "cloudsql.iam_authentication"
	not flags_index.value == "on"
}


deny[msg] {
	resource := input.resource.google_sql_database_instance[name]
    GCPPQL05_plsql_db_flag_check(resource)
	startswith(resource.database_version, "POSTGRES")

	msg := {
		# Mandatory fields
		"publicId": "GCPPQL05",
		"title": "GCPPQL05: Configuration for Cloud SQL IAM Database Authentication",
		"severity": "high",
		"msg": sprintf("resource.google_sql_database_instance[%s]", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "The flag cloudsql.iam_authentication must be turned on during the provisioning of the instance.",
		"impact": "Prudential levarage on GCP IAM for user access. This is to allow GCP IAM for Cloud SQL",
		"remediation": "Please enable cloudsql.iam_authentication when provisioning the resource. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
		"references": [""],
	}
}