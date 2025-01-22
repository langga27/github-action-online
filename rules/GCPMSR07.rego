package rules

deny[msg] {
    resource := input.resource.google_redis_instance[name]
    not resource.connect_mode == "PRIVATE_SERVICE_ACCESS"

    msg := {
        # Mandatory fields
        "publicId": "GCPMSR07",
        "title": "GCPMSR07: Private Service Access",
        "severity": "high",
        "msg": sprintf("resource.google_redis_instance[%s]", [name]),
        # Optional fields
        "issue": "Private Service Access allows application to reach to Memorystore via the internal IP address. Access to Memorystore must be restricted to internal IP address only",
        "impact": "Private service access must be used to reduce the risk on exposure and unauthorissed access",
        "remediation": "Please ensure private service access is used. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
        "references": ""
    }
}