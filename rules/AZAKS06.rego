package rules

azurerm_kubernetes_cluster_http_route(resource) {
    not resource.http_application_routing_enabled == null
    not resource.http_application_routing_enabled == false
    resource.http_application_routing_enabled == true
}

# This function is for provider's version 2.35.0
azurerm_kubernetes_cluster_http_route(resource) {
    detector := resource.addon_profile[_]
    legacy := detector.http_application_routing[_]
    not legacy.enabled == false
}

deny[msg] {
    resource := input.resource.azurerm_kubernetes_cluster[name]
    azurerm_kubernetes_cluster_http_route(resource)

    msg := {
        # Mandatory Fields
        "publicId": "AZAKS06",
        "title": "AZAKS06: HTTP Application Routing is not disabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_kubernetes_cluster[%s]", [name]),
        # Optional Fields
        "issue": "HTTP application routing should be disabled by default during the cluster setup to ensure SSL encrypted connection.",
        "impact": "Without SSL, the connection is susceptible to man-in-the-middle attack.",
        "remediation": "Please disable HTTP applciation routing. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/aks/browse"
    }
}