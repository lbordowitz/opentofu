terraform {
  backend "assure" {
    resource_group_name  = "storage-test-1"
    storage_account_name = "larrybostoragetest69420"
    container_name       = "arm-state"
    key                  = "tofu.tfstate"
  }
}

resource "random_string" "blob_suffix" {
  length  = 8
  special = false
  upper   = false
  keepers = {
    regen = timestamp()
  }
}
