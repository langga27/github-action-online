package rules

detect_ip_configuration_gcpmql06(resource) {
    indexedone := resource.settings[_]
    indexedtwo := indexedone.ip_configuration[_]
    not indexedtwo.ipv4_enabled == false
}

detect_ip_configuration_gcpmql06(resource) {
    indexedone := resource.settings[_]
    indexedtwo := indexedone.ip_configuration[_]
    indexedtwo.private_network == null
}

detect_ip_configuration_gcpmql06(resource) {
    indexedone := resource.settings[_]
    indexedtwo := indexedone.ip_configuration[_]
    indexedthree := indexedtwo.authorized_networks[_]
    indexedthree.value
}

deny[msg] {

  resource := input.resource.google_sql_database_instance[name]
  detect_ip_configuration_gcpmql06(resource)
  startswith(resource.database_version, "MYSQL")
  

  msg := {
    # Mandatory fields
    "publicId": "GCPMQL06",
    "title": "GCPMQL06: Network Access",
    "severity": "high",
    "msg": sprintf("resource.google_sql_database_instance[%s]", [name]),
    # Optional fields
    "issue": "Access to Group GCP Cloud SQL for MySQL Database must be restricted to Internal IP only via private services access, public IP must be disabled and no authorized networks is allowed",
    "impact": "A database that is publically accessible may have the risk of unauthorised access by malicious user.",
    "remediation": "Please deploy database with restriction to Internal IP only via private service access, with no authorized networks allowed. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
    "references": [""],
  }
}
