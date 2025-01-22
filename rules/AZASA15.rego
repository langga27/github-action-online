package rules

name_detection(resource) {
  not startswith(resource.name, "f")
  not startswith(resource.name, "bootdiag")
  not startswith(resource.name, "dbstorage")
  not endswith(resource.name, "vmdiag")
  not resource.tags.ApplicationName == "hcf"
  not resource.tags.application == "databricks"
}


deny[msg] {
  resource := input.resource.azurerm_storage_account[name]
  name_detection(resource)
  resource.public_network_access_enabled
  not resource.network_rules 

# "not resource.network_rules" will deny if there is no configuration that specify these atributes: ip_rule and virtual_network_subnet_ids
# More advance logic will be made in the next action plan

  msg := {
    # Mandatory fields
    "publicId": "AZASA15",
    "title": "AZASA15: Network Access Control is not restricted",
    "severity": "high",
    "msg": sprintf("input.resource.azurerm_storage_account[%s].public_network_access_enabled", [name]),
    # Optional fields
    "issue": "AZASA15: Azure Storage Accounts must only be deployed within a virtual network and/or Private endpoint, or firewall IP rules are set to limit network access to the storage account appropriately",
    "impact": "Storage Accounts that are publically accessible may lead to unauthorized access by malicious user.",
    "remediation": "Please deploy the storage account within a virtual network and/or private endpoint, or set firewall IP rules accordingly. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
    "references": ["https://code.pruconnect.net/projects/RTSRETM/repos/storage-account"],
  }
}

