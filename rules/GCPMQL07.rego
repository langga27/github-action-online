package rules

detect_ssl_gcpmql07(resource) {
    indexedone := resource.settings[_]
    indexedtwo := indexedone.ip_configuration[_]
    not indexedtwo.require_ssl == true
}

deny[msg] {

  resource := input.resource.google_sql_database_instance[name]
  detect_ssl_gcpmql07(resource)
  startswith(resource.database_version, "MYSQL")
  

  msg := {
    # Mandatory fields
    "publicId": "GCPMQL07",
    "title": "GCPMSQL07: Encryption in Transit",
    "severity": "high",
    "msg": sprintf("resource.google_sql_database_instance[%s]", [name]),
    # Optional fields
    "issue": "SSL encryption must be enabled for any Cloud SQL for all MYSQL instances",
    "impact": "By enabling SSL on Cloud SQL database, can significantly reduce these risks, enhance the security of data transmissions. Ensure that sensitive information remains confidential, unmodified, and secure during its journey between application and the database.",
    "remediation": "Please deploy with encryption in transit enabled. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
    "references": [""],
  }
}
