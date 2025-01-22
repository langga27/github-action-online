package rules

deny[msg] {
  resource := input.resource.google_container_cluster[name]
  not resource.enable_legacy_abac == false

  msg := {

    "publicId": "GCPCKE05",
    "title": "GCPGKE05: Legacy Authorization",
    "severity": "high",
    "msg": sprintf("resource.google_container_cluster[%s]", [name]),
    "issue": "Legacy authorization must be Disabled and to use GCP Identity instead for authentication and authorization.",
    "impact": "enabling Legacy Authorization instead of using GCP Identity, there is a risk where user access control is not managed adequately, increasing the risk of account compromised.",
    "remediation": "Please disable Legacy Authorization. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Gcp+Services for more details.",
    "references": ["https://code.pruconnect.net/projects/RTSRETM/repos/aks"],
  }
}