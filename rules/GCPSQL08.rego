package rules

# For static plan
cmekCheck(resource) {
    not resource.encryption_key_name
}

# # For tf-plan
# cmekCheck(resource) {
#     resource.encryption_key_name == false
# }

deny[msg] {
    resource := input.resource.google_sql_database_instance[name]
    startswith(resource.database_version, "SQLSERVER")
    cmekCheck(resource)
    
    msg := {
        # Mandatory fields
        "publicId": "GCPSQL08",
        "title": "GCPSQL08: Server-side Encryption",
        "severity": "high",
        "msg": sprintf("resource.google_sql_database_instance[%s]", [name]),
        # Optional fields
        "path": "resource > resource.google_sql_database_instance",
        "issue": "GCPSQL08: Prudential managed key (CMEK) must be used to wraps the Google KEK for Cloud SQL encryption",
        "impact": "To enhance the security of database",
        "remediation": sprintf("Update terraform variable in section resource.google_sql_database_instance[%s]", [name]),
        "references": "https://code.pruconnect.net/projects/RTSRETB/repos/gcp-foundation"        
    }
}