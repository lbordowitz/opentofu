data "azurerm_client_config" "current" {}

# Create an application and service account
resource "azuread_application" "tf_test_application" {
  display_name = "TF Test Application"
  owners       = [data.azurerm_client_config.current.object_id]
}

resource "azuread_service_principal" "tf_principal" {
  client_id                    = azuread_application.tf_test_application.client_id
  app_role_assignment_required = false
  owners                       = [data.azurerm_client_config.current.object_id]
}

# Role assignment, so that this can do anything in our tests.
resource "azurerm_role_assignment" "account_admin" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Storage Account Contributor"
  principal_id         = azuread_service_principal.tf_principal.object_id
}

# Secret credentials
resource "azuread_application_password" "pw" {
  application_id = azuread_application.tf_test_application.id
}

output "environment" {
    value = <<-EOT
            export TF_AZURE_TEST_CLIENT_ID=${azuread_application.tf_test_application.client_id}
            export TF_AZURE_TEST_SECRET=${azuread_application_password.pw.value}
            EOT
    sensitive = true
}
