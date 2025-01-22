package rules

detect_ssl_gcpsql07(resource) {
    indexedone := resource.settings[_]
    indexedtwo := indexedone.ip_configuration[_]
    not indexedtwo.require_ssl == true
}

deny[msg] {

  resource := input.resource.google_sql_database_instance[name]
  detect_ssl_gcpsql07(resource)
  startswith(resource.database_version, "SQLSERVER")
  

  msg := {
    # Mandatory fields
    "publicId": "GCPSQL07",
    "title": "GCPSQL07: Encryption in Transit",
    "severity": "high",
    "msg": sprintf("resource.google_sql_database_instance[%s]", [name]),
    # Optional fields
    "issue": "GCPSQL07: SSL encryption must be enabled for any Cloud SQL for all SQL Server instances",
    "impact": "By enabling SSL on Cloud SQL database, can significantly reduce these risks, enhance the security of data transmissions. Ensure that sensitive information remains confidential, unmodified, and secure during its journey between application and the database.",
    "remediation": "Please revise the 'settings > ip_configuration' atribute.",
    "references": [""],
  }
}
