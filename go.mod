module github.com/tarosky/gutenberg-notifier

go 1.15

require (
	github.com/iovisor/gobpf v0.2.1-0.20210508071522-2289761f1e20
	github.com/rakyll/statik v0.1.7
	github.com/urfave/cli/v2 v2.2.0
	go.uber.org/zap v1.15.0
)

replace github.com/iovisor/gobpf => github.com/harai/gobpf v0.2.1
