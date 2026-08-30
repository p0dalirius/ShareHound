module github.com/specterops/sharehound

go 1.23.0

toolchain go1.24.7

require (
	github.com/alexbrainman/sspi v0.0.0-20250919150558-7d374ff0d59e
	github.com/go-ldap/ldap/v3 v3.4.12
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/medianexapp/go-smb2 v0.0.0-20250425112922-92edacdefca5
	github.com/miekg/dns v1.1.57
	github.com/spf13/cobra v1.8.0
	golang.org/x/sync v0.6.0
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/cloudsoda/sddl v0.0.0-20250224235906-926454e91efc // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/tools v0.17.0 // indirect
)

replace github.com/medianexapp/go-smb2 => ./third_party/go-smb2
