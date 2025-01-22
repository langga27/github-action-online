package rules

detect_ip_configuration_gcpsql06(resource) {
    indexedone := resource.settings[_]
    indexedtwo := indexedone.ip_configuration[_]
    not indexedtwo.ipv4_enabled == false
}

detect_ip_configuration_gcpsql06(resource) {
    indexedone := resource.settings[_]
    indexedtwo := indexedone.ip_configuration[_]
    indexedtwo.private_network == null
}

detect_ip_configuration_gcpsql06(resource) {
    indexedone := resource.settings[_]
    indexedtwo := indexedone.ip_configuration[_]
    indexedthree := indexedtwo.authorized_networks[_]
    indexedthree.value
}

deny[msg] {

  resource := input.resource.google_sql_database_instance[name]
  detect_ip_configuration_gcpsql06(resource)
  startswith(resource.database_version, "SQLSERVER")
  

  msg := {
    # Mandatory fields
    "publicId": "GCPSQL06",
    "title": "GCPSQL06: Network Access",
    "severity": "high",
    "msg": sprintf("resource.google_sql_database_instance[%s]", [name]),
    # Optional fields
    "issue": "GCPSQL06: Access to Group GCP Cloud SQL for SQL Server Database must be restricted to Internal IP only via private services access, public IP must be disabled and no authorized networks is allowed",
    "impact": "The risk of not doing so could lead to unauthorized access, data breaches, and service disruptions.",
    "remediation": "Please revise the 'settings > ip_configuration' atribute.",
    "references": [""],
  }
}
