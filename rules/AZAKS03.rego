package rules

# this function is for newest provider's version
azurerm_kubernetes_cluster_cluster_azuread(resource) {
   rbac := resource.azure_active_directory_role_based_access_control
   rbac.azure_rbac_enabled == true
}

deny[msg] {
    resource := input.resource.azurerm_kubernetes_cluster[name]
    not azurerm_kubernetes_cluster_cluster_azuread(resource)
    azurerm_kubernetes_cluster_cluster_azuread(resource)

    msg := {
        # Mandatory Fields
        "publicId": "AZAKS03",
        "title": "AZAKS03: Kubernetes RBAC is not enabled",
        "severity": "high",
        "msg": sprintf("input.resource.azurerm_kubernetes_cluster[%s]", [name]),
        # Optional Fields
        "issue": "AKS must be configured to integrate with Azure Active Directory and use Kubernetes role-based access control (RBAC) based on a user's identity or directory group membership",
        "impact": "Without RBAC, there is a risk where user access control is not managed adequately, increasing the risk of account compromised.",
        "remediation": "Please enable RBAC. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
        "references": "https://code.pruconnect.net/projects/RTSRETM/repos/aks/browse"        
    }
}