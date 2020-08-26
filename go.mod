module github.com/tarosky/gutenberg-notifier

go 1.14

require (
	github.com/iovisor/gobpf v0.0.0-20200614202714-e6b321d32103
	github.com/rakyll/statik v0.1.7
	github.com/urfave/cli/v2 v2.2.0
	go.uber.org/zap v1.15.0
)

replace github.com/iovisor/gobpf => github.com/harai/gobpf v0.0.0-20200830051040-3869641b1144
