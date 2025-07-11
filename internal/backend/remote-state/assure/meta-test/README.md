This folder provides the necessary infrastructure for the acceptance tests in this backend. In order to use this, you must have administrative privileges within your Azure Subscription.

We recommend using CLI authentication and setting the subscription using the ARM_SUBSCRIPTION_ID environment variable:

```bash
$ az login
$ export ARM_SUBSCRIPTION_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Once those are set, you can initialize and apply the Open Tofu workspace:

```bash
$ tofu init
$ tofu apply
# When you're ready to obtain the secrets through environment variables
$ tofu apply -show-sensitive
```

You should see some environment variables that look like this:

```bash
export TF_AZURE_TEST_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export TF_AZURE_TEST_SECRET=some~secret~string
```

Copy and paste these into the command line to provide the secrets for the backend tests.

A file called `certs.pfx` should also be created, which can be placed in an appropriate directory and used for certificate authentication by setting the path appropriately, perhaps something like:

```bash
export TF_AZURE_TEST_CERT_PATH="meta-test/certs.pfx"
export TF_AZURE_TEST_CERT_PASSWORD=SoMePaSsWoRd
```
