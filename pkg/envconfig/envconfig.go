package envconfig

type EnvConfig struct {
	Port                       int    `envconfig:"PORT" required:"true"`
	Domain                     string `envconfig:"STS_DOMAIN" required:"true"`
	KMSKey                     string `envconfig:"KMS_KEY" required:"false"`
	AppID                      int64  `envconfig:"GITHUB_APP_ID" required:"true"`
	EventingIngress            string `envconfig:"EVENT_INGRESS_URI" required:"true"`
	AppSecretCertificateFile   string `envconfig:"APP_SECRET_CERTIFICATE_FILE" required:"false"`
	AppSecretCertificateEnvVar string `envconfig:"APP_SECRET_CERTIFICATE_ENV_VAR" required:"false"`
	Metrics                    bool   `envconfig:"METRICS" required:"false" default:"true"`
}
