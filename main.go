package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"unicode"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/rakyll/statik/fs"
	_ "github.com/tarosky/gutenberg-notifier/statik"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

//go:generate statik -src=c

// EventType is an event type
type EventType int32

var (
	log *zap.Logger
)

const (
	eventArg EventType = iota
	eventRet
)

const (
	cTaskCommLen = 16
	cNameMax     = 255
	cPathMax     = 4096
)

type config struct {
	exclComms     []string
	inclModes     []string
	inclFullNames []string
	inclExts      []string
	inclMntPaths  []string
}

func main() {
	app := cli.NewApp()
	app.Name = "notifier"
	app.Usage = "notify NFS file changes"

	app.Flags = []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "excl-comm",
			Aliases: []string{"ec"},
			Value:   &cli.StringSlice{},
			Usage:   "Command name to be excluded",
		},
		&cli.StringSliceFlag{
			Name:    "incl-mode",
			Aliases: []string{"im"},
			Value:   &cli.StringSlice{},
			Usage: "File operation mode to be included. Possible values are: " + fModeToString(
				^uint32(0)) + ".",
		},
		&cli.StringSliceFlag{
			Name:    "incl-fullname",
			Aliases: []string{"in"},
			Value:   &cli.StringSlice{},
			Usage:   "Full file name to be included.",
		},
		&cli.StringSliceFlag{
			Name:    "incl-ext",
			Aliases: []string{"ie"},
			Value:   &cli.StringSlice{},
			Usage:   "File with specified extension to be included. Include leading dot.",
		},
		&cli.StringSliceFlag{
			Name:    "incl-mntpath",
			Aliases: []string{"ir"},
			Value:   &cli.StringSlice{},
			Usage:   "Full path to the mount point where the file is located. Never include trailing slash.",
		},
	}

	app.Action = func(c *cli.Context) error {
		log = createLogger()
		defer log.Sync()

		run(config{
			exclComms:     c.StringSlice("excl-comm"),
			inclModes:     c.StringSlice("incl-mode"),
			inclFullNames: c.StringSlice("incl-fullname"),
			inclExts:      c.StringSlice("incl-ext"),
			inclMntPaths:  c.StringSlice("incl-mntpath"),
		})

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal("failed to run app", zap.Error(err))
	}
}

func unpackSource(name string) string {
	sfs, err := fs.New()
	if err != nil {
		log.Panic("embedded FS not found", zap.Error(err))
	}

	r, err := sfs.Open("/" + name)
	if err != nil {
		log.Panic("embedded file not found", zap.Error(err))
	}
	defer r.Close()

	contents, err := ioutil.ReadAll(r)
	if err != nil {
		log.Panic("failed to read embedded file", zap.Error(err))
	}

	return string(contents)
}

var source string = unpackSource("trace.c")

type eventCStruct struct {
	EvtType uint64
	Pid     uint64
	Comm    [cTaskCommLen]byte
	MntPath [cPathMax]byte
	Name    [cNameMax + 1]byte
	FMode   uint32
	Debug   uint32
}

func createLogger() *zap.Logger {
	log, err := zap.NewDevelopment(zap.WithCaller(false))
	if err != nil {
		panic("failed to initialize logger")
	}

	return log
}

const (
	maxArgs = 20
)

func configCommonTrace(m *bpf.Module) error {
	kprobeMnt, err := m.LoadKprobe("enter___mnt_want_write")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe("mnt_want_write", kprobeMnt, -1); err != nil {
		return err
	}

	kprobeNotifyChange, err := m.LoadKprobe("enter___notify_change")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe("notify_change", kprobeNotifyChange, -1); err != nil {
		return err
	}

	return nil
}

func configCloseTrace(m *bpf.Module) error {
	kprobe, err := m.LoadKprobe("enter___filp_close")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe("filp_close", kprobe, -1); err != nil {
		return err
	}

	kretprobe, err := m.LoadKprobe("return___filp_close")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe("filp_close", kretprobe, -1); err != nil {
		return err
	}

	return nil
}

func configUnlinkTrace(m *bpf.Module) error {
	kprobeUnlink, err := m.LoadKprobe("enter___syscall___unlink")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("unlink"), kprobeUnlink, -1); err != nil {
		return err
	}

	kprobeUnlinkAt, err := m.LoadKprobe("enter___syscall___unlinkat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("unlinkat"), kprobeUnlinkAt, -1); err != nil {
		return err
	}

	kprobeVFS, err := m.LoadKprobe("enter___vfs_unlink")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe("vfs_unlink", kprobeVFS, -1); err != nil {
		return err
	}

	kretprobeUnlink, err := m.LoadKprobe("return___syscall___unlink")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("unlink"), kretprobeUnlink, -1); err != nil {
		return err
	}

	kretprobeUnlinkAt, err := m.LoadKprobe("return___syscall___unlinkat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("unlinkat"), kretprobeUnlinkAt, -1); err != nil {
		return err
	}

	return nil
}

func configRenameTrace(m *bpf.Module) error {
	kprobeRename, err := m.LoadKprobe("enter___syscall___rename")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("rename"), kprobeRename, -1); err != nil {
		return err
	}

	kprobeRenameAt, err := m.LoadKprobe("enter___syscall___renameat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("renameat"), kprobeRenameAt, -1); err != nil {
		return err
	}

	kprobeRenameAt2, err := m.LoadKprobe("enter___syscall___renameat2")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("renameat2"), kprobeRenameAt2, -1); err != nil {
		return err
	}

	kprobeVFS, err := m.LoadKprobe("enter___vfs_rename")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe("vfs_rename", kprobeVFS, -1); err != nil {
		return err
	}

	kretprobeRename, err := m.LoadKprobe("return___syscall___rename")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("rename"), kretprobeRename, -1); err != nil {
		return err
	}

	kretprobeRenameAt, err := m.LoadKprobe("return___syscall___renameat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("renameat"), kretprobeRenameAt, -1); err != nil {
		return err
	}

	kretprobeRenameAt2, err := m.LoadKprobe("return___syscall___renameat2")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("renameat2"), kretprobeRenameAt2, -1); err != nil {
		return err
	}

	return nil
}

func configChmodTrace(m *bpf.Module) error {
	kprobeChmod, err := m.LoadKprobe("enter___syscall___chmod")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("chmod"), kprobeChmod, -1); err != nil {
		return err
	}

	kprobeFChmod, err := m.LoadKprobe("enter___syscall___fchmod")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("fchmod"), kprobeFChmod, -1); err != nil {
		return err
	}

	kprobeFChmodAt, err := m.LoadKprobe("enter___syscall___fchmodat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("fchmodat"), kprobeFChmodAt, -1); err != nil {
		return err
	}

	kretprobeChmod, err := m.LoadKprobe("return___syscall___chmod")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("chmod"), kretprobeChmod, -1); err != nil {
		return err
	}

	kretprobeFChmod, err := m.LoadKprobe("return___syscall___fchmod")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("fchmod"), kretprobeFChmod, -1); err != nil {
		return err
	}

	kretprobeFChmodAt, err := m.LoadKprobe("return___syscall___fchmodat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("fchmodat"), kretprobeFChmodAt, -1); err != nil {
		return err
	}

	return nil
}

func configChownTrace(m *bpf.Module) error {
	kprobeChown, err := m.LoadKprobe("enter___syscall___chown")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("chown"), kprobeChown, -1); err != nil {
		return err
	}

	kprobeFChown, err := m.LoadKprobe("enter___syscall___fchown")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("fchown"), kprobeFChown, -1); err != nil {
		return err
	}

	kprobeFChownAt, err := m.LoadKprobe("enter___syscall___fchownat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("fchownat"), kprobeFChownAt, -1); err != nil {
		return err
	}

	kprobeLChown, err := m.LoadKprobe("enter___syscall___lchown")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("lchown"), kprobeLChown, -1); err != nil {
		return err
	}

	kretprobeChown, err := m.LoadKprobe("return___syscall___chown")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("chown"), kretprobeChown, -1); err != nil {
		return err
	}

	kretprobeFChown, err := m.LoadKprobe("return___syscall___fchown")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("fchown"), kretprobeFChown, -1); err != nil {
		return err
	}

	kretprobeFChownAt, err := m.LoadKprobe("return___syscall___fchownat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("fchownat"), kretprobeFChownAt, -1); err != nil {
		return err
	}

	kretprobeLChown, err := m.LoadKprobe("return___syscall___lchown")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("lchown"), kretprobeLChown, -1); err != nil {
		return err
	}

	return nil
}

func configSyncTrace(m *bpf.Module) error {
	kretprobe, err := m.LoadKprobe("return___syscall___sync")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("sync"), kretprobe, -1); err != nil {
		return err
	}

	return nil
}

func configSyncFSTrace(m *bpf.Module) error {
	kretprobe, err := m.LoadKprobe("return___syscall___syncfs")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("syncfs"), kretprobe, -1); err != nil {
		return err
	}

	return nil
}

func configFSyncTrace(m *bpf.Module) error {
	kprobeFSync, err := m.LoadKprobe("enter___syscall___fsync")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("fsync"), kprobeFSync, -1); err != nil {
		return err
	}

	kprobeFDataSync, err := m.LoadKprobe("enter___syscall___fdatasync")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("fdatasync"), kprobeFDataSync, -1); err != nil {
		return err
	}

	kprobeVFSFSyncRange, err := m.LoadKprobe("enter___vfs_fsync_range")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe("vfs_fsync_range", kprobeVFSFSyncRange, -1); err != nil {
		return err
	}

	kretprobeFSync, err := m.LoadKprobe("return___syscall___fsync")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("fsync"), kretprobeFSync, -1); err != nil {
		return err
	}

	kretprobeFDataSync, err := m.LoadKprobe("return___syscall___fdatasync")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("fdatasync"), kretprobeFDataSync, -1); err != nil {
		return err
	}

	return nil
}

func configTruncateTrace(m *bpf.Module) error {
	kprobeTruncate, err := m.LoadKprobe("enter___syscall___truncate")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("truncate"), kprobeTruncate, -1); err != nil {
		return err
	}

	kprobeVFS, err := m.LoadKprobe("enter___vfs_truncate")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe("vfs_truncate", kprobeVFS, -1); err != nil {
		return err
	}

	kretprobeTruncate, err := m.LoadKprobe("return___syscall___truncate")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("truncate"), kretprobeTruncate, -1); err != nil {
		return err
	}

	return nil
}

func configLinkTrace(m *bpf.Module) error {
	kprobeLink, err := m.LoadKprobe("enter___syscall___link")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("link"), kprobeLink, -1); err != nil {
		return err
	}

	kprobeLinkAt, err := m.LoadKprobe("enter___syscall___linkat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("linkat"), kprobeLinkAt, -1); err != nil {
		return err
	}

	kprobeVFS, err := m.LoadKprobe("enter___vfs_link")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe("vfs_link", kprobeVFS, -1); err != nil {
		return err
	}

	kretprobeLink, err := m.LoadKprobe("return___syscall___link")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("link"), kretprobeLink, -1); err != nil {
		return err
	}

	kretprobeLinkAt, err := m.LoadKprobe("return___syscall___linkat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("linkat"), kretprobeLinkAt, -1); err != nil {
		return err
	}

	return nil
}

func configSymLinkTrace(m *bpf.Module) error {
	kprobeSymLink, err := m.LoadKprobe("enter___syscall___symlink")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("symlink"), kprobeSymLink, -1); err != nil {
		return err
	}

	kprobeSymLinkAt, err := m.LoadKprobe("enter___syscall___symlinkat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bpf.GetSyscallFnName("symlinkat"), kprobeSymLinkAt, -1); err != nil {
		return err
	}

	kprobeVFS, err := m.LoadKprobe("enter___vfs_symlink")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe("vfs_symlink", kprobeVFS, -1); err != nil {
		return err
	}

	kretprobeSymLink, err := m.LoadKprobe("return___syscall___symlink")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("symlink"), kretprobeSymLink, -1); err != nil {
		return err
	}

	kretprobeSymLinkAt, err := m.LoadKprobe("return___syscall___symlinkat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bpf.GetSyscallFnName("symlinkat"), kretprobeSymLinkAt, -1); err != nil {
		return err
	}

	return nil
}

func configTrace(m *bpf.Module, receiverChan chan []byte) *bpf.PerfMap {
	if err := configCommonTrace(m); err != nil {
		log.Fatal("failed to config common trace", zap.Error(err))
	}

	if err := configCloseTrace(m); err != nil {
		log.Fatal("failed to config CLOSE trace", zap.Error(err))
	}

	if err := configUnlinkTrace(m); err != nil {
		log.Fatal("failed to config UNLINK trace", zap.Error(err))
	}

	if err := configRenameTrace(m); err != nil {
		log.Fatal("failed to config RENAME trace", zap.Error(err))
	}

	if err := configChmodTrace(m); err != nil {
		log.Fatal("failed to config CHMOD trace", zap.Error(err))
	}

	if err := configChownTrace(m); err != nil {
		log.Fatal("failed to config CHOWN trace", zap.Error(err))
	}

	if err := configSyncTrace(m); err != nil {
		log.Fatal("failed to config SYNC trace", zap.Error(err))
	}

	if err := configSyncFSTrace(m); err != nil {
		log.Fatal("failed to config SYNCFS trace", zap.Error(err))
	}

	if err := configFSyncTrace(m); err != nil {
		log.Fatal("failed to config FSYNC trace", zap.Error(err))
	}

	if err := configTruncateTrace(m); err != nil {
		log.Fatal("failed to config TRUNCATE trace", zap.Error(err))
	}

	if err := configLinkTrace(m); err != nil {
		log.Fatal("failed to config LINK trace", zap.Error(err))
	}

	if err := configSymLinkTrace(m); err != nil {
		log.Fatal("failed to config SYMLINK trace", zap.Error(err))
	}

	table := bpf.NewTable(m.TableId("events"), m)

	perfMap, err := bpf.InitPerfMap(table, receiverChan, nil)
	if err != nil {
		log.Fatal("Failed to init perf map", zap.Error(err))
	}

	return perfMap
}

type fMode struct {
	val   uint32 // `fmode_t` is defined as `typedef unsigned __bitwise fmode_t;` in the kernel.
	name  string
	cName string
}

type fModeData struct {
	nameMap map[string]fMode
	valMap  map[uint32]fMode
	modes   []fMode
}

func newFModeSet() fModeData {
	fModes := []fMode{
		{0x1, "read", "FMODE_READ"},
		{0x2, "write", "FMODE_WRITE"},
		{0x4, "lseek", "FMODE_LSEEK"},
		{0x8, "pread", "FMODE_PREAD"},
		{0x10, "pwrite", "FMODE_PWRITE"},
		{0x20, "exec", "FMODE_EXEC"},
		{0x40, "ndelay", "FMODE_NDELAY"},
		{0x80, "excl", "FMODE_EXCL"},
		{0x100, "write_ioctl", "FMODE_WRITE_IOCTL"},
		{0x200, "32bithash", "FMODE_32BITHASH"},
		{0x400, "64bithash", "FMODE_64BITHASH"},
	}

	s := fModeData{
		nameMap: make(map[string]fMode, len(fModes)),
		valMap:  make(map[uint32]fMode, len(fModes)),
		modes:   make([]fMode, 0, len(fModes)),
	}

	for _, m := range fModes {
		s.nameMap[m.name] = m
		s.valMap[m.val] = m
		s.modes = append(s.modes, m)
	}

	return s
}

var fModeSet = newFModeSet()

type evtType struct {
	val  uint64
	name string
}

type evtTypeData struct {
	valMap   map[uint64]evtType
	evtTypes []evtType
}

func newEvtTypeSet() evtTypeData {
	evtTypes := []evtType{
		{0x1, "close"},
		{0x2, "unlink"},
		{0x4, "rename_src"},
		{0x8, "rename_dest"},
		{0x10, "chmod"},
		{0x20, "chown"},
		{0x40, "sync"},
		{0x80, "syncfs"},
		{0x100, "fsync"},
		{0x200, "truncate"},
		{0x400, "link"},
		{0x800, "symlink"},
	}

	s := evtTypeData{
		valMap:   make(map[uint64]evtType, len(evtTypes)),
		evtTypes: make([]evtType, 0, len(evtTypes)),
	}

	for _, e := range evtTypes {
		s.valMap[e.val] = e
		s.evtTypes = append(s.evtTypes, e)
	}

	return s
}

var evtTypeSet = newEvtTypeSet()

func (s fModeData) flagsToFModes(flags uint32) []fMode {
	setFlags := make([]fMode, 0, 8) // Typically 8 is enough.

	for _, m := range s.modes {
		if flags&m.val != 0 {
			setFlags = append(setFlags, m)
		}
	}

	return setFlags
}

func fModeToString(mode uint32) string {
	modes := fModeSet.flagsToFModes(mode)
	s := make([]string, 0, len(modes))

	for _, m := range modes {
		s = append(s, m.name)
	}

	return strings.Join(s, ",")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func validateExclComms(exclComms []string) error {
	for _, s := range exclComms {
		if !isASCII(s) {
			return fmt.Errorf("contains non-ASCII characters: %s", s)
		}

		if cTaskCommLen-1 < len(s) {
			return fmt.Errorf("maximum length is %d: too long: %s", cTaskCommLen-1, s)
		}
	}

	return nil
}

func generateExclCommsCode(commStrs []string) string {
	strs := make([]string, 0, len(commStrs))
	for _, cs := range commStrs {
		s := bytes.NewBufferString("\"")
		for _, c := range []byte(cs) {
			s.WriteString("\\x")
			s.WriteString(hex.EncodeToString([]byte{c}))
		}
		// "-1" is for automatically inserted null termination.
		s.WriteString(strings.Repeat("\\0", cTaskCommLen-1-len(cs)))
		s.WriteString("\"")
		strs = append(strs, s.String())
	}

	return strings.Join(strs, ",\n")
}

func validateInclModes(inclModes []string) error {
	for _, m := range inclModes {
		if _, ok := fModeSet.nameMap[m]; !ok {
			return fmt.Errorf("contains unknown mode: %s", m)
		}
	}

	return nil
}

func generateInclModesCode(inclModes []string) string {
	buf := bytes.Buffer{}
	for _, m := range inclModes {
		if _, err := buf.WriteString(" | "); err != nil {
			log.Panic("unknown error", zap.Error(err))
		}
		if _, err := buf.WriteString(fModeSet.nameMap[m].cName); err != nil {
			log.Panic("unknown error", zap.Error(err))
		}
	}

	return buf.String()
}

func validateInclFullNames(inclFullNames []string) error {
	for _, s := range inclFullNames {
		if !isASCII(s) {
			return fmt.Errorf("contains non-ASCII characters: %s", s)
		}

		if cNameMax < len(s) {
			return fmt.Errorf("maximum length is %d: too long: %s", cNameMax, s)
		}
	}

	return nil
}

func generateInclFullNames(inclFullNames []string) string {
	strs := make([]string, 0, len(inclFullNames))
	for _, fn := range inclFullNames {
		s := bytes.NewBufferString("\"")
		for _, c := range []byte(fn) {
			s.WriteString("\\x")
			s.WriteString(hex.EncodeToString([]byte{c}))
		}
		s.WriteString(strings.Repeat("\\0", cNameMax-len(fn)))
		s.WriteString("\"")
		strs = append(strs, s.String())
	}

	return strings.Join(strs, ",\n")
}

func validateInclExts(inclExts []string) error {
	for _, s := range inclExts {
		if !isASCII(s) {
			return fmt.Errorf("contains non-ASCII characters: %s", s)
		}

		if cNameMax < len(s) {
			return fmt.Errorf("maximum length is %d: too long: %s", cNameMax, s)
		}
	}

	return nil
}

func generateInclExts(inclExts []string) string {
	strs := make([]string, 0, len(inclExts))
	for _, ex := range inclExts {
		s := bytes.NewBufferString("\"")
		for _, c := range []byte(ex) {
			s.WriteString("\\x")
			s.WriteString(hex.EncodeToString([]byte{c}))
		}
		s.WriteString("\"")
		strs = append(strs, s.String())
	}

	return strings.Join(strs, ",\n")
}

func validateInclMntPaths(inclMntPaths []string) error {
	for _, s := range inclMntPaths {
		if !isASCII(s) {
			return fmt.Errorf("contains non-ASCII characters: %s", s)
		}

		if cPathMax-1 < len(s) {
			return fmt.Errorf("maximum length is %d: too long: %s", cPathMax-1, s)
		}
	}

	return nil
}

func generateInclMntPaths(inclMntPaths []string) string {
	strs := make([]string, 0, len(inclMntPaths))
	for _, path := range inclMntPaths {
		s := bytes.NewBufferString("\"")
		for _, c := range []byte(path) {
			s.WriteString("\\x")
			s.WriteString(hex.EncodeToString([]byte{c}))
		}
		s.WriteString("\"")
		strs = append(strs, s.String())
	}

	return strings.Join(strs, ",\n")
}

func generateSource(config config) string {
	if err := validateExclComms(config.exclComms); err != nil {
		log.Fatal("illegal excl-comms parameter", zap.Error(err))
	}
	exclCommsCode := generateExclCommsCode(config.exclComms)

	if err := validateInclModes(config.inclModes); err != nil {
		log.Fatal("illegal incl-modes parameter", zap.Error(err))
	}
	inclModesCode := generateInclModesCode(config.inclModes)

	if err := validateInclFullNames(config.inclFullNames); err != nil {
		log.Fatal("illegal incl-fullname parameter", zap.Error(err))
	}
	inclFullNamesCode := generateInclFullNames(config.inclFullNames)

	if err := validateInclExts(config.inclExts); err != nil {
		log.Fatal("illegal incl-ext parameter", zap.Error(err))
	}
	inclExtsCode := generateInclExts(config.inclExts)

	if err := validateInclMntPaths(config.inclMntPaths); err != nil {
		log.Fatal("illegal incl-mntpath parameter", zap.Error(err))
	}
	inclMntPathsCode := generateInclMntPaths(config.inclMntPaths)

	return strings.Replace(
		strings.Replace(
			strings.Replace(
				strings.Replace(
					strings.Replace(
						source,
						"/*EXCL_COMMS*/", exclCommsCode, -1),
					"/*INCL_MODES*/", inclModesCode, -1),
				"/*INCL_FULLNAMES*/", inclFullNamesCode, -1),
			"/*INCL_EXTS*/", inclExtsCode, -1),
		"/*INCL_MNTPATHS*/", inclMntPathsCode, -1)
}

func run(config config) {
	// m := bpf.NewModule(
	// 	generateSource(config), []string{}, bpf.DEBUG_PREPROCESSOR)
	m := bpf.NewModule(
		generateSource(config), []string{}, bpf.DEBUG_SOURCE)
	defer m.Close()

	channel := make(chan []byte, 8192)
	perfMap := configTrace(m, channel)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		for {
			data := <-channel

			var event eventCStruct
			if err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event); err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}

			evtType := evtTypeSet.valMap[event.EvtType]
			pid := event.Pid
			debug := event.Debug
			comm := cPointerToString(unsafe.Pointer(&event.Comm))
			name := cPointerToString(unsafe.Pointer(&event.Name))
			mntPath := cPointerToString(unsafe.Pointer(&event.MntPath))
			fMode := fModeToString(event.FMode)

			log.Info(
				"<-notify",
				zap.String("evttype", evtType.name),
				zap.Uint64("pid", pid),
				zap.String("mntpath", mntPath),
				zap.String("comm", comm),
				zap.String("mode", fMode),
				zap.String("name", name),
				zap.Uint32("debug", debug),
			)
		}
	}()

	// return

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
