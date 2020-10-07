package notify

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"unicode"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"
	"github.com/rakyll/statik/fs"

	// Load static assets
	_ "github.com/tarosky/gutenberg-notifier/statik"
	"go.uber.org/zap"
)

//go:generate statik -src=c

var (
	log *zap.Logger
)

const (
	cTaskCommLen = 16
	cNameMax     = 255
	cPathMax     = 4096
)

// Config configures parameters to filter what to be notified.
type Config struct {
	ExclComms     []string
	InclFModes    FMode
	InclFullNames []string
	InclExts      []string
	InclMntPaths  []string
	MaxMntDepth   int
	MaxDirDepth   int
	BpfDebug      uint
	Log           *zap.Logger
}

// SetModesFromString sets InclFModes field using string representation.
func (c *Config) SetModesFromString(inclFModes []string) error {
	fmode := FMode(0x0)

	for _, m := range inclFModes {
		m2, ok := fModeSet.nameMap[m]
		if !ok {
			return fmt.Errorf("contains unknown mode: %s", m)
		}
		fmode |= m2.val
	}

	c.InclFModes = fmode

	return nil
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
	Path    [cPathMax]byte
	MntPath [cPathMax]byte
	Name    [cNameMax + 1]byte
	FMode   uint32
	Debug   uint32
}

func configCommonTrace(m *bcc.Module) error {
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

func configCloseTrace(m *bcc.Module) error {
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

func configUnlinkTrace(m *bcc.Module) error {
	kprobeUnlink, err := m.LoadKprobe("enter___syscall___unlink")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("unlink"), kprobeUnlink, -1); err != nil {
		return err
	}

	kprobeUnlinkAt, err := m.LoadKprobe("enter___syscall___unlinkat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("unlinkat"), kprobeUnlinkAt, -1); err != nil {
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

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("unlink"), kretprobeUnlink, -1); err != nil {
		return err
	}

	kretprobeUnlinkAt, err := m.LoadKprobe("return___syscall___unlinkat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("unlinkat"), kretprobeUnlinkAt, -1); err != nil {
		return err
	}

	return nil
}

func configRenameTrace(m *bcc.Module) error {
	kprobeRename, err := m.LoadKprobe("enter___syscall___rename")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("rename"), kprobeRename, -1); err != nil {
		return err
	}

	kprobeRenameAt, err := m.LoadKprobe("enter___syscall___renameat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("renameat"), kprobeRenameAt, -1); err != nil {
		return err
	}

	kprobeRenameAt2, err := m.LoadKprobe("enter___syscall___renameat2")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("renameat2"), kprobeRenameAt2, -1); err != nil {
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

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("rename"), kretprobeRename, -1); err != nil {
		return err
	}

	kretprobeRenameAt, err := m.LoadKprobe("return___syscall___renameat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("renameat"), kretprobeRenameAt, -1); err != nil {
		return err
	}

	kretprobeRenameAt2, err := m.LoadKprobe("return___syscall___renameat2")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("renameat2"), kretprobeRenameAt2, -1); err != nil {
		return err
	}

	return nil
}

func configChmodTrace(m *bcc.Module) error {
	kprobeChmod, err := m.LoadKprobe("enter___syscall___chmod")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("chmod"), kprobeChmod, -1); err != nil {
		return err
	}

	kprobeFChmod, err := m.LoadKprobe("enter___syscall___fchmod")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("fchmod"), kprobeFChmod, -1); err != nil {
		return err
	}

	kprobeFChmodAt, err := m.LoadKprobe("enter___syscall___fchmodat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("fchmodat"), kprobeFChmodAt, -1); err != nil {
		return err
	}

	kretprobeChmod, err := m.LoadKprobe("return___syscall___chmod")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("chmod"), kretprobeChmod, -1); err != nil {
		return err
	}

	kretprobeFChmod, err := m.LoadKprobe("return___syscall___fchmod")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("fchmod"), kretprobeFChmod, -1); err != nil {
		return err
	}

	kretprobeFChmodAt, err := m.LoadKprobe("return___syscall___fchmodat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("fchmodat"), kretprobeFChmodAt, -1); err != nil {
		return err
	}

	return nil
}

func configChownTrace(m *bcc.Module) error {
	kprobeChown, err := m.LoadKprobe("enter___syscall___chown")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("chown"), kprobeChown, -1); err != nil {
		return err
	}

	kprobeFChown, err := m.LoadKprobe("enter___syscall___fchown")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("fchown"), kprobeFChown, -1); err != nil {
		return err
	}

	kprobeFChownAt, err := m.LoadKprobe("enter___syscall___fchownat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("fchownat"), kprobeFChownAt, -1); err != nil {
		return err
	}

	kprobeLChown, err := m.LoadKprobe("enter___syscall___lchown")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("lchown"), kprobeLChown, -1); err != nil {
		return err
	}

	kretprobeChown, err := m.LoadKprobe("return___syscall___chown")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("chown"), kretprobeChown, -1); err != nil {
		return err
	}

	kretprobeFChown, err := m.LoadKprobe("return___syscall___fchown")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("fchown"), kretprobeFChown, -1); err != nil {
		return err
	}

	kretprobeFChownAt, err := m.LoadKprobe("return___syscall___fchownat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("fchownat"), kretprobeFChownAt, -1); err != nil {
		return err
	}

	kretprobeLChown, err := m.LoadKprobe("return___syscall___lchown")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("lchown"), kretprobeLChown, -1); err != nil {
		return err
	}

	return nil
}

func configSyncTrace(m *bcc.Module) error {
	kretprobe, err := m.LoadKprobe("return___syscall___sync")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("sync"), kretprobe, -1); err != nil {
		return err
	}

	return nil
}

func configSyncFSTrace(m *bcc.Module) error {
	kretprobe, err := m.LoadKprobe("return___syscall___syncfs")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("syncfs"), kretprobe, -1); err != nil {
		return err
	}

	return nil
}

func configFSyncTrace(m *bcc.Module) error {
	kprobeFSync, err := m.LoadKprobe("enter___syscall___fsync")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("fsync"), kprobeFSync, -1); err != nil {
		return err
	}

	kprobeFDataSync, err := m.LoadKprobe("enter___syscall___fdatasync")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("fdatasync"), kprobeFDataSync, -1); err != nil {
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

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("fsync"), kretprobeFSync, -1); err != nil {
		return err
	}

	kretprobeFDataSync, err := m.LoadKprobe("return___syscall___fdatasync")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("fdatasync"), kretprobeFDataSync, -1); err != nil {
		return err
	}

	return nil
}

func configTruncateTrace(m *bcc.Module) error {
	kprobeTruncate, err := m.LoadKprobe("enter___syscall___truncate")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("truncate"), kprobeTruncate, -1); err != nil {
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

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("truncate"), kretprobeTruncate, -1); err != nil {
		return err
	}

	return nil
}

func configLinkTrace(m *bcc.Module) error {
	kprobeLink, err := m.LoadKprobe("enter___syscall___link")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("link"), kprobeLink, -1); err != nil {
		return err
	}

	kprobeLinkAt, err := m.LoadKprobe("enter___syscall___linkat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("linkat"), kprobeLinkAt, -1); err != nil {
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

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("link"), kretprobeLink, -1); err != nil {
		return err
	}

	kretprobeLinkAt, err := m.LoadKprobe("return___syscall___linkat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("linkat"), kretprobeLinkAt, -1); err != nil {
		return err
	}

	return nil
}

func configSymLinkTrace(m *bcc.Module) error {
	kprobeSymLink, err := m.LoadKprobe("enter___syscall___symlink")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("symlink"), kprobeSymLink, -1); err != nil {
		return err
	}

	kprobeSymLinkAt, err := m.LoadKprobe("enter___syscall___symlinkat")
	if err != nil {
		return err
	}

	if err := m.AttachKprobe(bcc.GetSyscallFnName("symlinkat"), kprobeSymLinkAt, -1); err != nil {
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

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("symlink"), kretprobeSymLink, -1); err != nil {
		return err
	}

	kretprobeSymLinkAt, err := m.LoadKprobe("return___syscall___symlinkat")
	if err != nil {
		return err
	}

	if err := m.AttachKretprobe(bcc.GetSyscallFnName("symlinkat"), kretprobeSymLinkAt, -1); err != nil {
		return err
	}

	return nil
}

func configTrace(m *bcc.Module, receiverChan chan []byte) *bcc.PerfMap {
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

	table := bcc.NewTable(m.TableId("events"), m)

	perfMap, err := bcc.InitPerfMap(table, receiverChan, nil)
	if err != nil {
		log.Fatal("Failed to init perf map", zap.Error(err))
	}

	return perfMap
}

// FMode corresponds to Linux kernel's f_mode, which tells what operation can perform
// for an open file.
type FMode uint32

type fModeTuple struct {
	val   FMode // `fmode_t` is defined as `typedef unsigned __bitwise fmode_t;` in the kernel.
	name  string
	cName string
}

type fModeData struct {
	nameMap map[string]fModeTuple
	valMap  map[FMode]fModeTuple
	modes   []fModeTuple
}

// FMode for closing files.
const (
	FModeRead FMode = 0x1 << iota
	FModeWrite
	FModeLseek
	FModePread
	FModePwrite
	FModeExec
	FModeNdelay
	FModeExcl
	FModeWriteIoctl
	FMode32bithash
	FMode64bithash
)

func newFModeSet() fModeData {
	fModes := []fModeTuple{
		{FModeRead, "read", "FMODE_READ"},
		{FModeWrite, "write", "FMODE_WRITE"},
		{FModeLseek, "lseek", "FMODE_LSEEK"},
		{FModePread, "pread", "FMODE_PREAD"},
		{FModePwrite, "pwrite", "FMODE_PWRITE"},
		{FModeExec, "exec", "FMODE_EXEC"},
		{FModeNdelay, "ndelay", "FMODE_NDELAY"},
		{FModeExcl, "excl", "FMODE_EXCL"},
		{FModeWriteIoctl, "write_ioctl", "FMODE_WRITE_IOCTL"},
		{FMode32bithash, "32bithash", "FMODE_32BITHASH"},
		{FMode64bithash, "64bithash", "FMODE_64BITHASH"},
	}

	s := fModeData{
		nameMap: make(map[string]fModeTuple, len(fModes)),
		valMap:  make(map[FMode]fModeTuple, len(fModes)),
		modes:   make([]fModeTuple, 0, len(fModes)),
	}

	for _, m := range fModes {
		s.nameMap[m.name] = m
		s.valMap[m.val] = m
		s.modes = append(s.modes, m)
	}

	return s
}

func (m *fModeData) decomposeBits(fMode FMode) []fModeTuple {
	fModes := []fModeTuple{}
	for _, m := range m.modes {
		if 0 < m.val&fMode {
			fModes = append(fModes, m)
		}
	}
	return fModes
}

var fModeSet = newFModeSet()

type evtType struct {
	val  EventType
	name string
}

type evtTypeData struct {
	valMap   map[EventType]evtType
	evtTypes []evtType
}

// EventType is an event type eBPF notfies.
type EventType uint64

// Event type to be notified.
const (
	EventTypeClose EventType = 0x1 << iota
	EventTypeUnlink
	EventTypeRenameSrc
	EventTypeRenameDest
	EventTypeChmod
	EventTypeChown
	EventTypeSync
	EventTypeSyncfs
	EventTypeFsync
	EventTypeTruncate
	EventTypeLink
	EventTypeSymlink
)

func newEvtTypeSet() evtTypeData {
	evtTypes := []evtType{
		{EventTypeClose, "close"},
		{EventTypeUnlink, "unlink"},
		{EventTypeRenameSrc, "rename_src"},
		{EventTypeRenameDest, "rename_dest"},
		{EventTypeChmod, "chmod"},
		{EventTypeChown, "chown"},
		{EventTypeSync, "sync"},
		{EventTypeSyncfs, "syncfs"},
		{EventTypeFsync, "fsync"},
		{EventTypeTruncate, "truncate"},
		{EventTypeLink, "link"},
		{EventTypeSymlink, "symlink"},
	}

	s := evtTypeData{
		valMap:   make(map[EventType]evtType, len(evtTypes)),
		evtTypes: make([]evtType, 0, len(evtTypes)),
	}

	for _, e := range evtTypes {
		s.valMap[e.val] = e
		s.evtTypes = append(s.evtTypes, e)
	}

	return s
}

var evtTypeSet = newEvtTypeSet()

func (m *fModeData) flagsToFModes(flags FMode) []fModeTuple {
	setFlags := make([]fModeTuple, 0, 8) // Typically 8 is enough.

	for _, m := range m.modes {
		if flags&m.val != 0 {
			setFlags = append(setFlags, m)
		}
	}

	return setFlags
}

func fModeToString(mode FMode) string {
	modes := fModeSet.flagsToFModes(mode)
	s := make([]string, 0, len(modes))

	for _, m := range modes {
		s = append(s, m.name)
	}

	return strings.Join(s, ",")
}

// AllFModes returns all available fmodes as string values.
func AllFModes() []string {
	modes := fModeSet.flagsToFModes(^FMode(0))
	s := make([]string, 0, len(modes))

	for _, m := range modes {
		s = append(s, m.name)
	}

	return s
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

func generateInclModesCode(inclFModes FMode) string {
	buf := bytes.Buffer{}
	for _, m := range fModeSet.decomposeBits(inclFModes) {
		if _, err := buf.WriteString(" | "); err != nil {
			log.Panic("unknown error", zap.Error(err))
		}
		if _, err := buf.WriteString(m.cName); err != nil {
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

func generateSource(config *Config) string {
	if err := validateExclComms(config.ExclComms); err != nil {
		log.Fatal("illegal excl-comms parameter", zap.Error(err))
	}
	exclCommsCode := generateExclCommsCode(config.ExclComms)

	inclModesCode := generateInclModesCode(config.InclFModes)

	if err := validateInclFullNames(config.InclFullNames); err != nil {
		log.Fatal("illegal incl-fullname parameter", zap.Error(err))
	}
	inclFullNamesCode := generateInclFullNames(config.InclFullNames)

	if err := validateInclExts(config.InclExts); err != nil {
		log.Fatal("illegal incl-ext parameter", zap.Error(err))
	}
	inclExtsCode := generateInclExts(config.InclExts)

	if err := validateInclMntPaths(config.InclMntPaths); err != nil {
		log.Fatal("illegal incl-mntpath parameter", zap.Error(err))
	}
	inclMntPathsCode := generateInclMntPaths(config.InclMntPaths)

	return strings.Replace(
		strings.Replace(
			strings.Replace(
				strings.Replace(
					strings.Replace(
						strings.Replace(
							strings.Replace(
								source,
								"/*EXCL_COMMS*/", exclCommsCode, -1),
							"/*INCL_MODES*/", inclModesCode, -1),
						"/*INCL_FULLNAMES*/", inclFullNamesCode, -1),
					"/*INCL_EXTS*/", inclExtsCode, -1),
				"/*INCL_MNTPATHS*/", inclMntPathsCode, -1),
			"/*MAX_MNT_DEPTH*/", strconv.Itoa(config.MaxMntDepth), -1),
		"/*MAX_DIR_DEPTH*/", strconv.Itoa(config.MaxDirDepth), -1)
}

// Event tells the details of notification.
type Event struct {
	EvtType EventType
	Pid     uint32
	Comm    string
	MntPath string
	Path    string
	Name    string
	FMode   FMode
}

func absolutePath(path, mntPath string) string {
	if path == "" {
		return ""
	}

	if mntPath == "/" {
		return path
	}

	return mntPath + path
}

// Run starts compiling eBPF code and then notifying of file updates.
func Run(ctx context.Context, config *Config, eventCh chan<- *Event) {
	log = config.Log
	m := bcc.NewModule(generateSource(config), []string{}, config.BpfDebug)
	defer m.Close()

	channel := make(chan []byte, 8192)
	perfMap := configTrace(m, channel)

	go func() {
		log.Info("tracing started")
		for {
			select {
			case <-ctx.Done():
				close(eventCh)
				return
			case data := <-channel:
				var cEvent eventCStruct
				if err := binary.Read(bytes.NewBuffer(data), bcc.GetHostByteOrder(), &cEvent); err != nil {
					fmt.Printf("failed to decode received data: %s\n", err)
					continue
				}

				evtType := evtTypeSet.valMap[EventType(cEvent.EvtType)]
				pid := uint32(cEvent.Pid)
				debug := cEvent.Debug
				comm := cPointerToString(unsafe.Pointer(&cEvent.Comm))
				name := cPointerToString(unsafe.Pointer(&cEvent.Name))
				path := cPointerToString(unsafe.Pointer(&cEvent.Path))
				mntPath := cPointerToString(unsafe.Pointer(&cEvent.MntPath))
				fMode := FMode(cEvent.FMode)

				absPath := absolutePath(path, mntPath)

				log.Debug(
					"event",
					zap.String("evttype", evtType.name),
					zap.Uint32("pid", pid),
					zap.String("path", absPath),
					zap.String("mntpath", mntPath),
					zap.String("comm", comm),
					zap.String("mode", fModeToString(fMode)),
					zap.String("name", name),
					zap.Uint32("debug", debug),
				)

				eventCh <- &Event{
					EvtType: evtType.val,
					Comm:    comm,
					FMode:   fMode,
					MntPath: mntPath,
					Name:    name,
					Pid:     pid,
				}
			}
		}
	}()

	perfMap.Start()
	<-ctx.Done()
	perfMap.Stop()
}
