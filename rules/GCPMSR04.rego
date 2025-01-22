package rules

deny[msg] {
	resource := input.resource.google_redis_instance[name]
	not resource.auth_enabled == true
    

	msg := {
		# Mandatory fields
		"publicId": "GCPMSR04",
		"title": "GCPMSR04: Access Control for Data Plane",
		"severity": "high",
		"msg": sprintf("resource.google_redis_instance[%s]", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "GCPMSR04: AUTH string is used to must be used to manage application access to the memorystore.",
		"impact": "Anyone who can reach the IP and port of the Redis instance can connect to it and perform operations without any authentication or security measures in place",
		"remediation": "Enable auth to manage application access to the memorystore",
		"references": [""],
	}
}