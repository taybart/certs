package integrations

import (
	"context"
	"crypto"
	"fmt"

	"github.com/1password/onepassword-sdk-go"
	"github.com/taybart/env"
)

func GetCertFrom1Pass() (crypto.PrivateKey, error) {
	env.Add([]string{"OP_SERVICE_ACCOUNT_TOKEN", "OP_PRIVATE_KEY_URI"})

	token := env.Get("OP_SERVICE_ACCOUNT_TOKEN")

	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(token),
		// TODO: Set the following to your own integration name and version.
		onepassword.WithIntegrationInfo("My 1Password Integration", "v1.0.0"),
	)
	if err != nil {
		return nil, err
	}
	secret, err := client.Secrets().Resolve(
		context.TODO(), "op://Service Account/Production JIN CA Key/rootCA.key",
	)
	if err != nil {
		return nil, err
	}
	fmt.Println("secret from op", secret)
	return nil, nil
}
