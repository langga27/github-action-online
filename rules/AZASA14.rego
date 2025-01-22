package rules

public_access_AZASA14(resource) {
  resource.allow_nested_items_to_be_public == true
}

public_access_AZASA14(resource) {
  resource.allow_blob_public_access == true
}

public_access_AZASA14(resource) {
  resource.allow_nested_items_to_be_public == "true"
}

public_access_AZASA14(resource) {
  resource.allow_blob_public_access == "true"
}

exception_AZASA14(resource) {
  not startswith(resource.name, "f")
  not startswith(resource.name, "bootdiag")
  not startswith(resource.name, "dbstorage")
  not endswith(resource.name, "vmdiag")
  not resource.tags.ApplicationName == "hcf"
}

deny[msg] {
	resource := input.resource.azurerm_storage_account[name]
  exception_AZASA14(resource)
  public_access_AZASA14(resource)

  msg := {
    # Mandatory fields
    "publicId": "AZASA14",
    "title": "AZASA14: Public Access for Containers and Blobs is enabled",
    "severity": "high",
    "msg": sprintf("input.resource.azurerm_storage_account[%s]", [name]),
    # Optional fields
    "issue": "Public Access for Containters and Blobs must be disabled.",
    "impact": "Publically accessible Containers and Blobs may lead to unauthorized access by malicious users.",
    "remediation": "Public access level settings for Containers and Blobs should be set to disabled. You may refer to the baseline documents in https://collaborate.pruconnect.net/display/GWISPCS/GISP+endorsed+Azure+Services for more details.",
    "references": ["https://code.pruconnect.net/projects/RTSRETM/repos/storage-account"],
  }
}