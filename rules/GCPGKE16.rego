package rules

intranode_visibility_check(resource){
    resource.enable_intranode_visibility == true
}

deny[msg] {
    resource := input.resource.google_container_cluster[name]
    not intranode_visibility_check(resource)

    msg := {
        # Mandatory fields
        "publicId": "GCPGKE16",
        "title": "GCPGKE16: Intranode Visibility",
        "severity": "high",
        "msg": sprintf("resource.google_container_cluster[%s]", [name]),
        # Optional fields
        "path": "resource > resource.google_container_cluster",
        "issue": "Intranode Visibility must be set to Enabled. Enabling intranode visibility makes intranode Pod-to-Pod traffic visible to the GCP networking fabric",
        "impact": "Visibility within intranode are required for security investigation, in the event of a security incident.",
        "remediation": "Please enable intranode visibility when provisioning GKE. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
        "references": ""
    }
}