terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      version = "4.14.0"
    }
  }
}

provider "azurerm" {
  features {}
  resource_provider_registrations = "none"
  subscription_id = var.subscription_id
}

resource "azurerm_resource_group" "example" {
  name     = var.resource_group_name
  location = "Southeast Asia"
}


resource "azurerm_network_security_rule" "example" {
  name                        = "test123"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_ranges          = ["8080"]
  destination_port_ranges     = [8079,8081]
  source_address_prefixes       = ["10.10.10.0/24"] 
  destination_address_prefixes  = ["1.10.10.0/24"]
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.example.name
}

resource "azurerm_network_security_group" "example" {
  name                = "acceptanceTestSecurityGroup1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name


  tags = {
    environment = "Production"
  }

}
