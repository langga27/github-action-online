package rules

uniform_bucket_level_access_check(resource) {
    resource.uniform_bucket_level_access == true
}

# For exception
startswith_pvc_velero(resource) {
    not startswith(resource.name, "pvc-")
	not startswith(resource.name, "velero-")    
}

deny[msg] {
    resource := input.resource.google_storage_bucket[name]
    not uniform_bucket_level_access_check(resource)
    startswith_pvc_velero(resource)

    msg := {
        # Mandatory fields
        "publicId": "GCPGCS03",
        "title": "GCPGCS03: Identity and Access Management",
        "severity": "high",
        "msg": sprintf("resource.google_storage_bucket[%s]", [name]),
        # Optional fields
        "path": "resource > resource.google_storage_bucket",
        "issue": "Uniform access control must be used to leverage Identity and Access Management (IAM) to manage the permission",
        "impact": "This setting enforces uniform access controls on all objects within a bucket, regardless of whether individual objects have their own access control settings",
        "remediation": "Please enable Uniform access control for the bucket. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details",
        "references": "https://code.pruconnect.net/projects/RTSRETB/repos/gcp-foundation"        
    }
}