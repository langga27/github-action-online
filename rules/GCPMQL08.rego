package rules

# For static plan
cmekCheck_gcpmql08(resource) {
    not resource.encryption_key_name
}

# # For tf-plan
# cmekCheck(resource) {
#     resource.encryption_key_name == false
# }

deny[msg] {
    resource := input.resource.google_sql_database_instance[name]
    startswith(resource.database_version, "MYSQL")
    cmekCheck_gcpmql08(resource)
    
    msg := {
        # Mandatory fields
        "publicId": "GCPMQL08",
        "title": "GCPMQL08: Server-side Encryption",
        "severity": "high",
        "msg": sprintf("resource.google_sql_database_instance[%s]", [name]),
        # Optional fields
        "path": "resource > resource.google_sql_database_instance",
        "issue": "Prudential managed key (CMEK) must be used to wraps the Google KEK for Cloud SQL encryption",
        "impact": "If CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the Google's encryption key and the encrypted data.",
        "remediation": "Please enable CMEK. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETB/repos/gcp-foundation"        
    }
}