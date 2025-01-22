package rules

# For execption
gcs_startwith_pvc_and_valero(resource) {
    startswith(resource.name, "pvc-")
}

gcs_startwith_pvc_and_valero(resource) {
	startswith(resource.name, "velero-")
}

# For tf-plan.json
encryption_at_rest_check(resource) {
    resource.encryption == []
}

deny[msg] {
    resource := input.resource.google_storage_bucket[name]
    not gcs_startwith_pvc_and_valero(resource)    
    encryption_at_rest_check(resource)

    msg := {
        # Mandatory fields
        "publicId": "GCPGCS04",
        "title": "GCPGCS04: Encryption at Rest",
        "severity": "high",
        "msg": sprintf("resource.google_storage_bucket[%s]", [name]),
        # Optional fields
        "path": "resource > resource.google_storage_bucket",
        "issue": "GCPGCS04: Group GCP Cloud Storage must be configured to use Prudential managed key (Customer-managed key) to encrypts data on the server side",
        "impact": "This setting enforces uniform access controls on all objects within a bucket, regardless of whether individual objects have their own access control settings",
        "remediation": "Please enable CMEK for bucket provisioning. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details",
        "references": "https://code.pruconnect.net/projects/RTSRETB/repos/gcp-foundation"
    }
}