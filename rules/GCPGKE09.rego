package rules

cmek_missing(resource) {
    cmek_check := resource.node_config[_]
    is_null(cmek_check.boot_disk_kms_key)
}

deny[msg] {
    resource := input.resource.google_container_cluster[name]
    cmek_missing(resource)

    msg := {
        # Mandatory fields
        "publicId": "GCPGKE09",
        "title": "GCPGKE09: Encryption at rest",
        "severity": "high",
        "msg": sprintf("resource.google_container_cluster[%s]", [name]),
        # Optional fields
        "path": "resource > resource.google_container_cluster",
        "issue": "Customer Managed Encryption Keys (CMEK) must be used for both Node boot disks and attached disks",
        "impact": "f CMEK is not used, there is a risk where data can be exfiltrate and read by malicious actor, upon obtaining the Google's encryption key and the encrypted data.",
        "remediation": "Please enable CMEK. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
        "references": ""
    }
}