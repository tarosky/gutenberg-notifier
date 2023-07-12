module github.com/tarosky/gutenberg-notifier

go 1.20

require (
	github.com/iovisor/gobpf v0.2.1-0.20221005153822-16120a1bf4d4
	github.com/rakyll/statik v0.1.7
	github.com/urfave/cli/v2 v2.25.7
	go.uber.org/zap v1.24.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
)

replace github.com/iovisor/gobpf => github.com/harai/gobpf v0.2.2
