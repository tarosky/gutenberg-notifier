#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

// Limit directory depth to ascend to pass verifier
#define MAX_MNT_DEPTH /*MAX_MNT_DEPTH*/
#define MAX_DIR_DEPTH /*MAX_DIR_DEPTH*/

// Event types these probes emit
#define GNEVT_CLOSE ((u64)0x1)
#define GNEVT_UNLINK ((u64)0x2)
#define GNEVT_RENAME_SRC ((u64)0x4)
#define GNEVT_RENAME_DEST ((u64)0x8)
#define GNEVT_CHMOD ((u64)0x10)
#define GNEVT_CHOWN ((u64)0x20)
#define GNEVT_SYNC ((u64)0x40)
#define GNEVT_SYNCFS ((u64)0x80)
#define GNEVT_FSYNC ((u64)0x100)
#define GNEVT_TRUNCATE ((u64)0x200)
#define GNEVT_LINK ((u64)0x400)
#define GNEVT_SYMLINK ((u64)0x800)

struct mount {
  struct hlist_node mnt_hash;
  struct mount *mnt_parent;
  struct dentry *mnt_mountpoint;
  struct vfsmount mnt;
  // omitted...
};

struct data_t {
  u64 evttype;
  u64 pid; // PID as in the userspace term (i.e. task->tgid in kernel)
  char comm[TASK_COMM_LEN];

  // This order is particularly important to pass the verifier.
  // Verifier doesn't care if a pointer goes out of a struct member
  // as long as it is contained in the struct.
  //
  char path[PATH_MAX];
  char mntpath[PATH_MAX];
  char name[NAME_MAX + 1];

  u32 f_mode; // Used only when evttype is GNEVT_CLOSE
  u32 debug;
} __attribute__((__packed__)) __attribute__((__aligned__(8)));

BPF_PERF_OUTPUT(events);
BPF_HASH(evt_close, u64, struct data_t);
BPF_HASH(evt_syscall, u64, struct data_t);
BPF_HASH(evt_rename_dest, u64, struct data_t);
BPF_HASH(rally, u64, u8);
BPF_HASH(mnt_dentry_addr, u64, u64);
BPF_PERCPU_ARRAY(store, struct data_t, 1);
BPF_PERCPU_ARRAY(store2, struct data_t, 1);

static int is_equal8(const void *s1, const void *s2, int wlen) {
  u64 *ss1 = (u64 *)s1;
  u64 *ss2 = (u64 *)s2;
#pragma unroll
  for (int i = 0; i < wlen; i++) {
    if (ss1[i] != ss2[i]) {
      return 0;
    }
  }
  return 1;
}

static int is_equal1(const void *s1, const void *s2, int blen) {
  char *ss1 = (char *)s1;
  char *ss2 = (char *)s2;
#pragma unroll
  for (int i = 0; i < blen; i++) {
    if (ss1[i] != ss2[i]) {
      return 0;
    }
  }
  return 1;
}

static int is_excl_comm(const char *comm) {
  const char *excl_comms[] = {
      // Length of each string, including null terminator,
      // must be equal to TASK_COMM_LEN.
      /*EXCL_COMMS*/
  };
  int count = (int)(sizeof(excl_comms) / sizeof(*excl_comms));

#pragma unroll
  for (int i = 0; i < count; i++) {
    if (is_equal8(comm, excl_comms[i], TASK_COMM_LEN / 8)) {
      return 1;
    }
  }

  return 0;
}

static int is_incl_mode(u32 mode) {
  const u32 filter = 0x0 /*INCL_MODES*/;

  if (filter == 0x0) {
    return 1;
  }

  if ((filter & mode) == 0x0) {
    return 0;
  }

  return 1;
}

// return values:
//   0: candidates provided but not found
//  -1: no candidates and hence not found
//   1: found
static int is_incl_fullname(const char *name) {
  const char *incl_fullnames[] = {
      /*INCL_FULLNAMES*/
  };
  int count = (int)(sizeof(incl_fullnames) / sizeof(*incl_fullnames));

  if (count == 0) {
    return -1;
  }

#pragma unroll
  for (int i = 0; i < count; i++) {
    if (is_equal8(name, incl_fullnames[i], (NAME_MAX + 1) / 8)) {
      return 1;
    }
  }

  return 0;
}

static int is_incl_ext_sub(const char *name, int name_len, const char *incl_ext,
                           int ext_len) {
  if (name_len < ext_len) {
    return 0;
  }

  return is_equal1(&name[name_len - ext_len], incl_ext, ext_len);
}

// return values:
//   0: candidates provided but not found
//  -1: no candidates and hence not found
//   1: found
static int is_incl_ext(const char *name) {
  const char *incl_exts[] = {
      /*INCL_EXTS*/
  };
  int count = (int)(sizeof(incl_exts) / sizeof(*incl_exts));

  if (count == 0) {
    return -1;
  }

  int i;
  // Fast forward...
#pragma unroll
  for (i = 0; i < (NAME_MAX + 1) / 8; i++) {
    if (((u64 *)name)[i] == 0x0) {
      i *= 8;
      break;
    }
  }

  if (i == 0) {
    return 0;
  }

  // And then rewind a bit.
  int n; // Used for supporting unrolling.
#pragma unroll
  for (i -= 1, n = 1; 0 <= i && n < 8; i--, n++) {
    if (name[i] != '\0') {
      break;
    }
  }

  int name_len = i + 1;

#pragma unroll
  for (int j = 0; j < count; j++) {
    if (is_incl_ext_sub(name, name_len, incl_exts[j], strlen(incl_exts[j]))) {
      return 1;
    }
  }

  return 0;
}

static int is_incl_name(const char *name) {
  int fnres = is_incl_fullname(name);

  if (fnres == 1) {
    return 1;
  }

  int extres = is_incl_ext(name);

  if (extres == 1) {
    return 1;
  }

  return fnres == -1 && extres == -1;
}

static __always_inline struct data_t *get_data(u64 evttype) {
  int zero = 0;
  struct data_t *data = store.lookup(&zero);
  if (data == NULL) {
    return 0;
  }
  data->evttype = evttype;
  return data;
}

static __always_inline struct data_t *get_data2(u64 evttype) {
  int zero = 0;
  struct data_t *data = store2.lookup(&zero);
  if (data == NULL) {
    return 0;
  }
  data->evttype = evttype;
  return data;
}

static __always_inline struct mount *enclosing_mount(struct vfsmount *mnt) {
  return (struct mount *)((void *)mnt - ((size_t) & ((struct mount *)0)->mnt));
}

static __always_inline int mnt_has_parent(struct mount *mnt) {
  u64 mnt_addr, mnt_parent_addr;
  bpf_probe_read_kernel(&mnt_addr, sizeof(u64), &mnt);
  bpf_probe_read_kernel(&mnt_parent_addr, sizeof(u64), &mnt->mnt_parent);
  return mnt_addr != mnt_parent_addr;
}

static __always_inline int is_root(struct dentry *d) {
  u64 d_addr, d_parent_addr;
  bpf_probe_read_kernel(&d_addr, sizeof(u64), &d);
  bpf_probe_read_kernel(&d_parent_addr, sizeof(u64), &d->d_parent);
  return d_addr == d_parent_addr;
}

static __always_inline void store_mnt_dentry_addr(u64 ptg_id, struct vfsmount *mnt) {
  u64 addr;
  bpf_probe_read_kernel(&addr, sizeof(u64), &mnt->mnt_root);
  mnt_dentry_addr.update(&ptg_id, &addr);
}

/**
 * `pos & (PATH_MAX - 1)` is a technique to tell the upper bound to the verifier.
 * This works only if PATH_MAX is power of 2.
 */
static __always_inline void copy_mount_path(char *mnt_path, struct vfsmount *mnt) {
  struct mount *mnt_start = enclosing_mount(mnt);

  u32 pos = 0;

  {
    struct mount *mnt = mnt_start;
    struct dentry *d = mnt->mnt_mountpoint;
#pragma unroll
    for (int i = 0; i < MAX_MNT_DEPTH; i++) {
      if (is_root(d)) {
        if (mnt_has_parent(mnt)) {
          mnt = mnt->mnt_parent;
          d = mnt->mnt_mountpoint->d_parent;
          continue;
        }
        break;
      }

      u32 len;
      bpf_probe_read_kernel(&len, sizeof(u32), &d->d_name.len);
      pos += len + 1; // Add separator
      d = d->d_parent;
    }
  }

  {
    if (pos == 0) {
      mnt_path[0] = '/';
      mnt_path[1] = '\0';
      return;
    }

    mnt_path[pos & (PATH_MAX - 1)] = '\0';

    struct mount *mnt = mnt_start;
    struct dentry *d = mnt->mnt_mountpoint;
#pragma unroll
    for (int i = 0; i < MAX_MNT_DEPTH; i++) {
      if (is_root(d)) {
        if (mnt_has_parent(mnt)) {
          mnt = mnt->mnt_parent;
          d = mnt->mnt_mountpoint->d_parent;
          continue;
        }
        break;
      }

      u32 len;
      bpf_probe_read_kernel(&len, sizeof(u32), &d->d_name.len);
      pos -= len;
      bpf_probe_read_kernel(&mnt_path[pos & (PATH_MAX - 1)], len & NAME_MAX,
                            d->d_name.name);

      pos--;
      mnt_path[pos & (PATH_MAX - 1)] = '/';

      d = d->d_parent;
    }
  }
}

/**
 * `pos & (PATH_MAX - 1)` is a technique to tell the upper bound to the verifier.
 * This works only if PATH_MAX is power of 2.
 */
static __always_inline void copy_file_path(char *path, struct dentry *dentry,
                                           u64 mnt_addr) {
  u32 pos = 0;

  {
    struct dentry *d = dentry;
#pragma unroll
    for (int i = 0; i < MAX_DIR_DEPTH; i++) {
      u64 dentry_addr;
      bpf_probe_read_kernel(&dentry_addr, sizeof(u64), &d);
      if (is_root(d) || mnt_addr == dentry_addr) {
        break;
      }

      u32 len;
      bpf_probe_read_kernel(&len, sizeof(u32), &d->d_name.len);
      pos += len + 1;

      d = d->d_parent;
    }
  }

  {
    path[pos & (PATH_MAX - 1)] = '\0';

    struct dentry *d = dentry;
#pragma unroll
    for (int i = 0; i < MAX_DIR_DEPTH; i++) {
      u64 dentry_addr;
      bpf_probe_read_kernel(&dentry_addr, sizeof(u64), &d);
      if (is_root(d) || mnt_addr == dentry_addr) {
        break;
      }

      u32 len;
      bpf_probe_read_kernel(&len, sizeof(u32), &d->d_name.len);

      pos -= len;
      bpf_probe_read_kernel(&path[pos & (PATH_MAX - 1)], len & NAME_MAX, d->d_name.name);
      pos--;
      path[pos & (PATH_MAX - 1)] = '/';

      d = d->d_parent;
    }
  }
}

static __always_inline void copy_file_name(char *name, struct dentry *dentry) {
  u32 name_len;
  bpf_probe_read_kernel(&name_len, sizeof(name_len), &dentry->d_name.len);
  u32 d_name_len = (NAME_MAX < name_len) ? NAME_MAX : name_len;
  u64 *n = (u64 *)name;
#pragma unroll
  for (int i = 0; i < (NAME_MAX + 1) / 8; i++) {
    n[i] = 0x0;
  }
  bpf_probe_read_kernel(name, d_name_len, dentry->d_name.name);
}

static __always_inline void copy_command_name(char *name) {
  bpf_get_current_comm(name, TASK_COMM_LEN);
}

static int is_incl_mntpath(const char *mnt_path) {
  const char *incl_mntpaths[] = {
      /*INCL_MNTPATHS*/
  };
  int count = (int)(sizeof(incl_mntpaths) / sizeof(*incl_mntpaths));

  if (count == 0) {
    return 1;
  }

#pragma unroll
  for (int i = 0; i < count; i++) {
    int len = strlen(incl_mntpaths[i]) + 1; // Include null terminator

    if (!is_equal8(incl_mntpaths[i], mnt_path, len / 8)) {
      continue;
    }

    if (is_equal1(&incl_mntpaths[i][8 * (len / 8)], &mnt_path[8 * (len / 8)], len % 8)) {
      return 1;
    }
  }

  return 0;
}

static __always_inline void init_rally(u64 ptg_id) {
  u8 ral = 0x1;
  rally.update(&ptg_id, &ral);
}

static __always_inline int update_rally(u64 ptg_id, u8 flag) {
  u8 *ral;
  ral = rally.lookup(&ptg_id);
  if (ral == NULL) {
    return 0;
  }
  *ral |= flag;
  rally.update(&ptg_id, ral);
  return 1;
}

static __always_inline int rallied(u64 ptg_id, u8 flags) {
  u8 *ral;
  ral = rally.lookup(&ptg_id);
  if (ral == NULL) {
    return 0;
  }
  rally.delete(&ptg_id);
  if (*ral == flags) {
    return 1;
  }
  return 0;
}

static __always_inline int is_directory(struct dentry *dentry) {
  return dentry->d_flags & (DCACHE_DIRECTORY_TYPE | DCACHE_AUTODIR_TYPE);
}

static __always_inline void copy_file_path_from_path(char *path,
                                                     const struct path *f_path) {
  u64 mnt_addr;
  bpf_probe_read_kernel(&mnt_addr, sizeof(u64), &f_path->mnt->mnt_root);
  copy_file_path(path, f_path->dentry, mnt_addr);
}

////////////////////////////////////////////////////////////////////////////////
//
// Common Functions
//
////////////////////////////////////////////////////////////////////////////////

// Kprobe:
// int mnt_want_write(struct vfsmount *m);
//
int enter___mnt_want_write(struct pt_regs *ctx, struct vfsmount *m) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }

  if (data->evttype & (GNEVT_UNLINK | GNEVT_RENAME_SRC | GNEVT_CHMOD | GNEVT_CHOWN |
                       GNEVT_LINK | GNEVT_SYMLINK)) {

    // This dentry address is used to construct a correct file path.
    u64 addr;
    bpf_probe_read_kernel(&addr, sizeof(u64), &m->mnt_root);
    mnt_dentry_addr.update(&ptg_id, &addr);

    // Copy full path to the mount point
    //
    copy_mount_path(data->mntpath, m);
    if (!is_incl_mntpath(data->mntpath)) {
      return 0;
    }

    if (!update_rally(ptg_id, 0x2)) {
      return 0;
    };
    evt_syscall.update(&ptg_id, data);
  }

  {
    struct data_t *data_dest = evt_rename_dest.lookup(&ptg_id);
    if (data_dest != NULL) {
      // Copy full path to the mount point
      //
      copy_mount_path(data_dest->mntpath, m);

      if (!update_rally(ptg_id, 0x4)) {
        return 0;
      };
      evt_rename_dest.update(&ptg_id, data_dest);
    }
  }

  return 0;
}

// Kprobe:
// int notify_change(struct dentry * dentry, struct iattr * attr, struct inode
// **delegated_inode);
//
int enter___notify_change(struct pt_regs *ctx, struct dentry *dentry, struct iattr *attr,
                          struct inode **delegated_inode) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }

  if (data->evttype & (GNEVT_CHMOD | GNEVT_CHOWN)) {
    // Copy file name
    //
    copy_file_name(data->name, dentry);
    if (!is_incl_name(data->name)) {
      return 0;
    }

    u64 *mnt_addr = mnt_dentry_addr.lookup(&ptg_id);
    if (mnt_addr == NULL) {
      return 0;
    }

    // Copy full path
    //
    copy_file_path(data->path, dentry, *mnt_addr);

    if (!update_rally(ptg_id, 0x4)) {
      return 0;
    };

    evt_syscall.update(&ptg_id, data);
  }

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Detect Close
//
// * close(2)
// * implicit close
//
////////////////////////////////////////////////////////////////////////////////

// Kprobe:
// int filp_close(struct file *filp, fl_owner_t id);
//
int enter___filp_close(struct pt_regs *ctx, struct file *filp, fl_owner_t id) {
  struct data_t *data = get_data(GNEVT_CLOSE);
  if (data == NULL) {
    return 0;
  }

  // Copy command name
  //
  copy_command_name(data->comm);
  if (is_excl_comm(data->comm)) {
    return 0;
  }

  // Copy mode
  //
  bpf_probe_read_kernel(&data->f_mode, sizeof(data->f_mode), &filp->f_mode);
  if (!is_incl_mode(data->f_mode)) {
    return 0;
  }

  // Copy file name
  //
  copy_file_name(data->name, filp->f_path.dentry);
  if (!is_incl_name(data->name)) {
    return 0;
  }

  // Copy full path of the mount point
  //
  copy_mount_path(data->mntpath, filp->f_path.mnt);
  if (!is_incl_mntpath(data->mntpath)) {
    return 0;
  }

  // Copy full path
  //
  copy_file_path_from_path(data->path, &filp->f_path);

  // Copy pid
  //
  u64 ptg_id = bpf_get_current_pid_tgid();
  data->pid = ptg_id >> 32;

  evt_close.update(&ptg_id, data);

  return 0;
}

// Kretprobe:
// int filp_close(struct file *filp, fl_owner_t id);
//
int return___filp_close(struct pt_regs *ctx) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_close.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }
  evt_close.delete(&ptg_id);

  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Detect Unlink
//
// * unlink(2)
// * unlinkat(2)
//
////////////////////////////////////////////////////////////////////////////////

static __always_inline int enter_unlink(struct pt_regs *ctx) {
  struct data_t *data = get_data(GNEVT_UNLINK);
  if (data == NULL) {
    return 0;
  }
  u64 ptg_id = bpf_get_current_pid_tgid();
  init_rally(ptg_id);

  // Copy command name
  //
  copy_command_name(data->comm);
  if (is_excl_comm(data->comm)) {
    return 0;
  }

  // Copy pid
  //
  data->pid = ptg_id >> 32;

  evt_syscall.update(&ptg_id, data);

  return 0;
}

// Kprobe:
// int unlink(const char __user *pathname);
//
int enter___syscall___unlink(struct pt_regs *ctx, const char __user *pathname) {
  return enter_unlink(ctx);
}

// Kprobe:
// int unlinkat(int dfd, const char __user *pathname, int flag);
//
int enter___syscall___unlinkat(struct pt_regs *ctx, int dfd, const char __user *pathname,
                               int flag) {
  return enter_unlink(ctx);
}

// Kprobe:
// int vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode
// **delegated_inode);
//
int enter___vfs_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry,
                       struct inode **delegated_inode) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL || data->evttype != GNEVT_UNLINK) {
    return 0;
  }

  // Copy file name
  //
  copy_file_name(data->name, dentry);
  if (!is_incl_name(data->name)) {
    return 0;
  }

  u64 *mnt_addr = mnt_dentry_addr.lookup(&ptg_id);
  if (mnt_addr == NULL) {
    return 0;
  }

  // Copy full path
  //
  copy_file_path(data->path, dentry, *mnt_addr);

  if (!update_rally(ptg_id, 0x4)) {
    return 0;
  };

  evt_syscall.update(&ptg_id, data);

  return 0;
}

static __always_inline int return_unlink(struct pt_regs *ctx) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }
  evt_syscall.delete(&ptg_id);

  mnt_dentry_addr.delete(&ptg_id);

  if (!rallied(ptg_id, 0x7)) {
    return 0;
  }

  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  // Copy mode
  //
  data->f_mode = 0;

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

// Kretprobe:
// int unlink(const char __user *pathname);
//
int return___syscall___unlink(struct pt_regs *ctx) { return return_unlink(ctx); }

// Kretprobe:
// int unlinkat(int dfd, const char __user *pathname, int flag);
//
int return___syscall___unlinkat(struct pt_regs *ctx) { return return_unlink(ctx); }

////////////////////////////////////////////////////////////////////////////////
//
// Detect Rename
//
// * rename(2)
// * renameat(2)
// * renameat2(2)
//
////////////////////////////////////////////////////////////////////////////////

static __always_inline int enter_rename(struct pt_regs *ctx) {
  struct data_t *data_src = get_data(GNEVT_RENAME_SRC);
  struct data_t *data_dest = get_data2(GNEVT_RENAME_DEST);
  if (data_src == NULL || data_dest == NULL) {
    return 0;
  }
  u64 ptg_id = bpf_get_current_pid_tgid();
  init_rally(ptg_id);

  // Copy command name
  //
  copy_command_name(data_src->comm);
  copy_command_name(data_dest->comm);
  if (is_excl_comm(data_src->comm)) { // No need to check data_dest
    return 0;
  }

  // Copy pid
  //
  data_dest->pid = data_src->pid = ptg_id >> 32;

  evt_syscall.update(&ptg_id, data_src);
  evt_rename_dest.update(&ptg_id, data_dest);

  return 0;
}

// Kprobe:
// int rename(const char __user *oldname, const char __user *newname);
//
int enter___syscall___rename(struct pt_regs *ctx, const char __user *oldname,
                             const char __user *newname) {
  return enter_rename(ctx);
}

// Kprobe:
// int renameat(int olddfd, const char __user *oldname,	int newdfd, const char __user
// *newname);
//
int enter___syscall___renameat(struct pt_regs *ctx, int olddfd,
                               const char __user *oldname, int newdfd,
                               const char __user *newname) {
  return enter_rename(ctx);
}

// Kprobe:
// int renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user
// *newname, unsigned int flags);
//
int enter___syscall___renameat2(struct pt_regs *ctx, int olddfd,
                                const char __user *oldname, int newdfd,
                                const char __user *newname, unsigned int flags) {
  return enter_rename(ctx);
}

// Kprobe:
// int vfs_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
// struct dentry *new_dentry, struct inode **delegated_inode, unsigned int flags)
//
int enter___vfs_rename(struct pt_regs *ctx, struct inode *old_dir,
                       struct dentry *old_dentry, struct inode *new_dir,
                       struct dentry *new_dentry, struct inode **delegated_inode,
                       unsigned int flags) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data_src = evt_syscall.lookup(&ptg_id);
  struct data_t *data_dest = evt_rename_dest.lookup(&ptg_id);
  if (data_src == NULL || data_dest == NULL || data_src->evttype != GNEVT_RENAME_SRC) {
    return 0;
  }

  // Copy file name
  //
  if (is_directory(old_dentry)) {
    copy_file_name(data_src->name, old_dentry);
    copy_file_name(data_dest->name, new_dentry);
  } else {
    copy_file_name(data_src->name, old_dentry);
    copy_file_name(data_dest->name, new_dentry);
    if (!is_incl_name(data_src->name) && !is_incl_name(data_dest->name)) {
      return 0;
    }
  }

  u64 *mnt_addr = mnt_dentry_addr.lookup(&ptg_id);
  if (mnt_addr == NULL) {
    return 0;
  }

  // Copy full path
  //
  copy_file_path(data_src->path, old_dentry, *mnt_addr);
  copy_file_path(data_dest->path, new_dentry, *mnt_addr);

  if (!update_rally(ptg_id, 0x8)) {
    return 0;
  };
  evt_syscall.update(&ptg_id, data_src);
  evt_rename_dest.update(&ptg_id, data_dest);

  return 0;
}

static __always_inline int return_rename(struct pt_regs *ctx) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data_src = evt_syscall.lookup(&ptg_id);
  struct data_t *data_dest = evt_rename_dest.lookup(&ptg_id);
  if (data_src == NULL || data_dest == NULL) {
    return 0;
  }
  evt_syscall.delete(&ptg_id);
  evt_rename_dest.delete(&ptg_id);

  mnt_dentry_addr.delete(&ptg_id);

  if (!rallied(ptg_id, 0xf)) {
    return 0;
  }

  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  // Copy mode
  //
  data_src->f_mode = data_dest->f_mode = 0;

  data_src->debug = data_dest->debug = 0;
  events.perf_submit(ctx, data_src, sizeof(struct data_t));
  events.perf_submit(ctx, data_dest, sizeof(struct data_t));

  return 0;
}

// Kretprobe:
// int rename(const char __user *oldname, const char __user *newname);
//
int return___syscall___rename(struct pt_regs *ctx) { return return_rename(ctx); }

// Kretprobe:
// int renameat(int olddfd, const char __user *oldname,	int newdfd, const char __user
// *newname);
//
int return___syscall___renameat(struct pt_regs *ctx) { return return_rename(ctx); }

// Kretprobe:
// int renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user
// *newname, unsigned int flags);
//
int return___syscall___renameat2(struct pt_regs *ctx) { return return_rename(ctx); }

////////////////////////////////////////////////////////////////////////////////
//
// Detect permisson change
//
// * chmod(2)
// * fchmod(2)
// * fchmodat(2)
//
////////////////////////////////////////////////////////////////////////////////

static __always_inline int enter_chmod(struct pt_regs *ctx) {
  struct data_t *data = get_data(GNEVT_CHMOD);
  if (data == NULL) {
    return 0;
  }
  u64 ptg_id = bpf_get_current_pid_tgid();
  init_rally(ptg_id);

  // Copy command name
  //
  copy_command_name(data->comm);
  if (is_excl_comm(data->comm)) {
    return 0;
  }

  // Copy pid
  //
  data->pid = ptg_id >> 32;

  evt_syscall.update(&ptg_id, data);

  return 0;
}

// Kprobe:
// int chmod(const char __user * filename, umode_t mode);
//
int enter___syscall___chmod(struct pt_regs *ctx, const char __user *filename,
                            umode_t mode) {
  return enter_chmod(ctx);
}

// Kprobe:
// int fchmod(unsigned int fd, umode_t mode);
//
int enter___syscall___fchmod(struct pt_regs *ctx, unsigned int fd, umode_t mode) {
  return enter_chmod(ctx);
}

// Kprobe:
// int fchmodat(int dfd, const char __user *filename, umode_t mode);
//
int enter___syscall___fchmodat(struct pt_regs *ctx, int dfd, const char __user *filename,
                               umode_t mode) {
  return enter_chmod(ctx);
}

static __always_inline int return_chmod(struct pt_regs *ctx) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }
  evt_syscall.delete(&ptg_id);

  if (!rallied(ptg_id, 0x7)) {
    return 0;
  }

  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  // Copy mode
  //
  data->f_mode = 0;

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

// Kretprobe:
// int chmod(const char __user * filename, umode_t mode);
//
int return___syscall___chmod(struct pt_regs *ctx) { return return_chmod(ctx); }

// Kretprobe:
// int fchmod(unsigned int fd, umode_t mode);
//
int return___syscall___fchmod(struct pt_regs *ctx) { return return_chmod(ctx); }

// Kretprobe:
// int fchmodat(int dfd, const char __user *filename, umode_t mode);
//
int return___syscall___fchmodat(struct pt_regs *ctx) { return return_chmod(ctx); }

////////////////////////////////////////////////////////////////////////////////
//
// Detect owner change
//
// * chown(2)
// * fchown(2)
// * fchownat(2)
// * lchown(2)
//
////////////////////////////////////////////////////////////////////////////////

static __always_inline int enter_chown(struct pt_regs *ctx) {
  struct data_t *data = get_data(GNEVT_CHOWN);
  if (data == NULL) {
    return 0;
  }
  u64 ptg_id = bpf_get_current_pid_tgid();
  init_rally(ptg_id);

  // Copy command name
  //
  copy_command_name(data->comm);
  if (is_excl_comm(data->comm)) {
    return 0;
  }

  // Copy pid
  //
  data->pid = ptg_id >> 32;

  evt_syscall.update(&ptg_id, data);

  return 0;
}

// Kprobe:
// int chown(const char __user *filename, uid_t user, gid_t group);
//
int enter___syscall___chown(struct pt_regs *ctx, const char __user *filename, uid_t user,
                            gid_t group) {
  return enter_chown(ctx);
}

// Kprobe:
// int fchown(unsigned int fd, uid_t user, gid_t group);
//
int enter___syscall___fchown(struct pt_regs *ctx, unsigned int fd, uid_t user,
                             gid_t group) {
  return enter_chown(ctx);
}

// Kprobe:
// int fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag);
//
int enter___syscall___fchownat(struct pt_regs *ctx, int dfd, const char __user *filename,
                               uid_t user, gid_t group, int flag) {
  return enter_chown(ctx);
}

// Kprobe:
// int lchown(const char __user *filename, uid_t user, gid_t group);
//
int enter___syscall___lchown(struct pt_regs *ctx, const char __user *filename, uid_t user,
                             gid_t group) {
  return enter_chown(ctx);
}

static __always_inline int return_chown(struct pt_regs *ctx) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }
  evt_syscall.delete(&ptg_id);

  mnt_dentry_addr.delete(&ptg_id);

  if (!rallied(ptg_id, 0x7)) {
    return 0;
  }

  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  // Copy mode
  //
  data->f_mode = 0;

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

// Kretprobe:
// int chown(const char __user * filename, umode_t mode);
//
int return___syscall___chown(struct pt_regs *ctx) { return return_chown(ctx); }

// Kretprobe:
// int fchown(unsigned int fd, uid_t user, gid_t group);
//
int return___syscall___fchown(struct pt_regs *ctx) { return return_chown(ctx); }

// Kretprobe:
// int fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag);
//
int return___syscall___fchownat(struct pt_regs *ctx) { return return_chown(ctx); }

// Kretprobe:
// int lchown(const char __user *filename, uid_t user, gid_t group);
//
int return___syscall___lchown(struct pt_regs *ctx) { return return_chown(ctx); }

////////////////////////////////////////////////////////////////////////////////
//
// Detect system-wide sync
//
// * sync(2)
//
////////////////////////////////////////////////////////////////////////////////

// Kprobe:
// int sync();
//
int return___syscall___sync(struct pt_regs *ctx) {
  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  struct data_t *data = get_data(GNEVT_SYNC);
  if (data == NULL) {
    return 0;
  }

  // Copy command name
  //
  copy_command_name(data->comm);
  // Never filter with command names since "sync" is always system-wide.

  // Copy pid
  //
  u64 ptg_id = bpf_get_current_pid_tgid();
  data->pid = ptg_id >> 32;

  // Unused fields
  //
  data->f_mode = 0;
  data->name[0] = '\0';
  data->mntpath[0] = '\0';
  data->path[0] = '\0';

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Detect filesystem sync
//
// * syncfs(2)
//
////////////////////////////////////////////////////////////////////////////////

// Kprobe:
// int syncfs(int fd);
//
int return___syscall___syncfs(struct pt_regs *ctx) {
  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  struct data_t *data = get_data(GNEVT_SYNCFS);
  if (data == NULL) {
    return 0;
  }

  // Copy command name
  //
  copy_command_name(data->comm);
  if (is_excl_comm(data->comm)) {
    return 0;
  }

  // Copy pid
  //
  u64 ptg_id = bpf_get_current_pid_tgid();
  data->pid = ptg_id >> 32;

  // Unused fields
  //
  data->f_mode = 0;
  data->name[0] = '\0';
  data->mntpath[0] = '\0';
  data->path[0] = '\0';

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Detect file sync
//
// * fsync(2)
// * fdatasync(2)
//
////////////////////////////////////////////////////////////////////////////////

static __always_inline int enter_fsync(struct pt_regs *ctx) {
  struct data_t *data = get_data(GNEVT_FSYNC);
  if (data == NULL) {
    return 0;
  }
  u64 ptg_id = bpf_get_current_pid_tgid();
  init_rally(ptg_id);

  // Copy command name
  //
  copy_command_name(data->comm);
  if (is_excl_comm(data->comm)) {
    return 0;
  }

  // Copy pid
  //
  data->pid = ptg_id >> 32;

  evt_syscall.update(&ptg_id, data);

  return 0;
}

// Kprobe:
// int fsync(unsigned int fd);
//
int enter___syscall___fsync(struct pt_regs *ctx, unsigned int fd) {
  return enter_fsync(ctx);
}

// Kprobe:
// int fdatasync(unsigned int fd);
//
int enter___syscall___fdatasync(struct pt_regs *ctx, unsigned int fd) {
  return enter_fsync(ctx);
}

// Kprobe:
// int vfs_fsync_range(struct file *file, loff_t start, loff_t end, int datasync);
//
int enter___vfs_fsync_range(struct pt_regs *ctx, struct file *file, loff_t start,
                            loff_t end, int datasync) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL || data->evttype != GNEVT_FSYNC) {
    return 0;
  }

  // Copy file name
  //
  copy_file_name(data->name, file->f_path.dentry);
  if (!is_incl_name(data->name)) {
    return 0;
  }

  // Copy full path of the mount point
  //
  copy_mount_path(data->mntpath, file->f_path.mnt);
  if (!is_incl_mntpath(data->mntpath)) {
    return 0;
  }

  // Copy full path
  //
  copy_file_path_from_path(data->path, &file->f_path);

  if (!update_rally(ptg_id, 0x2)) {
    return 0;
  };

  evt_syscall.update(&ptg_id, data);

  return 0;
}

static __always_inline int return_fsync(struct pt_regs *ctx) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }
  evt_syscall.delete(&ptg_id);

  if (!rallied(ptg_id, 0x3)) {
    return 0;
  }

  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  // Copy mode
  //
  data->f_mode = 0;

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

// Kretprobe:
// int fsync(unsigned int fd);
//
int return___syscall___fsync(struct pt_regs *ctx) { return return_fsync(ctx); }

// Kretprobe:
// int fdatasync(unsigned int fd);
//
int return___syscall___fdatasync(struct pt_regs *ctx) { return return_fsync(ctx); }

////////////////////////////////////////////////////////////////////////////////
//
// Detect truncate
//
// * truncate(2)
//
////////////////////////////////////////////////////////////////////////////////

// Kprobe:
// int truncate(const char __user *path, long length);
//
int enter___syscall___truncate(struct pt_regs *ctx, const char __user *path,
                               long length) {
  struct data_t *data = get_data(GNEVT_TRUNCATE);
  if (data == NULL) {
    return 0;
  }
  u64 ptg_id = bpf_get_current_pid_tgid();
  init_rally(ptg_id);

  // Copy command name
  //
  copy_command_name(data->comm);
  if (is_excl_comm(data->comm)) {
    return 0;
  }

  // Copy pid
  //
  data->pid = ptg_id >> 32;

  evt_syscall.update(&ptg_id, data);

  return 0;
}

// Kprobe:
// long vfs_truncate(const struct path *path, loff_t length);
//
int enter___vfs_truncate(struct pt_regs *ctx, const struct path *path, loff_t length) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL || data->evttype != GNEVT_TRUNCATE) {
    return 0;
  }

  // Copy file name
  //
  copy_file_name(data->name, path->dentry);
  if (!is_incl_name(data->name)) {
    return 0;
  }

  // Copy full path to the mount point
  //
  copy_mount_path(data->mntpath, path->mnt);
  if (!is_incl_mntpath(data->mntpath)) {
    return 0;
  }

  // Copy full path
  //
  copy_file_path_from_path(data->path, path);

  if (!update_rally(ptg_id, 0x2)) {
    return 0;
  };

  evt_syscall.update(&ptg_id, data);

  return 0;
}

// Kretprobe:
// int truncate(const char __user *path, long length);
//
int return___syscall___truncate(struct pt_regs *ctx) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }
  evt_syscall.delete(&ptg_id);

  if (!rallied(ptg_id, 0x3)) {
    return 0;
  }

  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  // Copy mode
  //
  data->f_mode = 0;

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Detect hard link
//
// * link(2)
// * linkat(2)
//
////////////////////////////////////////////////////////////////////////////////

static __always_inline int enter_link(struct pt_regs *ctx) {
  struct data_t *data = get_data(GNEVT_LINK);
  if (data == NULL) {
    return 0;
  }
  u64 ptg_id = bpf_get_current_pid_tgid();
  init_rally(ptg_id);

  // Copy command name
  //
  copy_command_name(data->comm);
  if (is_excl_comm(data->comm)) {
    return 0;
  }

  // Copy pid
  //
  data->pid = ptg_id >> 32;

  evt_syscall.update(&ptg_id, data);

  return 0;
}

// Kprobe:
// int link(const char __user *oldname, const char __user *newname);
//
int enter___syscall___link(struct pt_regs *ctx, const char __user *oldname,
                           const char __user *newname) {
  return enter_link(ctx);
}

// Kprobe:
// int linkat(int olddfd, const char __user *oldname, int newdfd, const char __user
// *newname, int flags);
//
int enter___syscall___linkat(struct pt_regs *ctx, int olddfd, const char __user *oldname,
                             int newdfd, const char __user *newname, int flags) {
  return enter_link(ctx);
}

// Kprobe:
// int vfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry,
// struct inode **delegated_inode);
//
int enter___vfs_link(struct pt_regs *ctx, struct dentry *old_dentry, struct inode *dir,
                     struct dentry *new_dentry, struct inode **delegated_inode) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL || data->evttype != GNEVT_LINK) {
    return 0;
  }

  // Copy file name
  //
  copy_file_name(data->name, new_dentry);
  if (!is_incl_name(data->name)) {
    return 0;
  }

  u64 *mnt_addr = mnt_dentry_addr.lookup(&ptg_id);
  if (mnt_addr == NULL) {
    return 0;
  }

  // Copy full path
  //
  copy_file_path(data->path, new_dentry, *mnt_addr);

  if (!update_rally(ptg_id, 0x4)) {
    return 0;
  };

  evt_syscall.update(&ptg_id, data);

  return 0;
}

static __always_inline int return_link(struct pt_regs *ctx) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }
  evt_syscall.delete(&ptg_id);

  mnt_dentry_addr.delete(&ptg_id);

  if (!rallied(ptg_id, 0x7)) {
    return 0;
  }

  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  // Copy mode
  //
  data->f_mode = 0;

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

// Kretprobe:
// int link(const char __user *oldname, const char __user *newname);
//
int return___syscall___link(struct pt_regs *ctx) { return return_link(ctx); }

// Kretprobe:
// int linkat(int olddfd, const char __user *oldname, int newdfd, const char __user
// *newname, int flags);
//
int return___syscall___linkat(struct pt_regs *ctx) { return return_link(ctx); }

////////////////////////////////////////////////////////////////////////////////
//
// Detect symbolic link
//
// * symlink(2)
// * symlinkat(2)
//
////////////////////////////////////////////////////////////////////////////////

static __always_inline int enter_symlink(struct pt_regs *ctx) {
  struct data_t *data = get_data(GNEVT_SYMLINK);
  if (data == NULL) {
    return 0;
  }
  u64 ptg_id = bpf_get_current_pid_tgid();
  init_rally(ptg_id);

  // Copy command name
  //
  copy_command_name(data->comm);
  if (is_excl_comm(data->comm)) {
    return 0;
  }

  // Copy pid
  //
  data->pid = ptg_id >> 32;

  evt_syscall.update(&ptg_id, data);

  return 0;
}

// Kprobe:
// int symlink(const char __user *oldname, const char __user *newname);
//
int enter___syscall___symlink(struct pt_regs *ctx, const char __user *oldname,
                              const char __user *newname) {
  return enter_symlink(ctx);
}

// Kprobe:
// int symlinkat(int olddfd, const char __user *oldname, int newdfd, const char __user
// *newname, int flags);
//
int enter___syscall___symlinkat(struct pt_regs *ctx, int olddfd,
                                const char __user *oldname, int newdfd,
                                const char __user *newname, int flags) {
  return enter_symlink(ctx);
}

// Kprobe:
// int vfs_symlink(struct inode *dir, struct dentry *dentry, const char *oldname);
//
int enter___vfs_symlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry,
                        const char *oldname) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL || data->evttype != GNEVT_SYMLINK) {
    return 0;
  }

  // Copy file name
  //
  copy_file_name(data->name, dentry);
  // Things a symlink points to can change between file and directory.
  // Checking file name at this time isn't meaningful.

  u64 *mnt_addr = mnt_dentry_addr.lookup(&ptg_id);
  if (mnt_addr == NULL) {
    return 0;
  }

  // Copy full path
  //
  copy_file_path(data->path, dentry, *mnt_addr);

  if (!update_rally(ptg_id, 0x4)) {
    return 0;
  };

  evt_syscall.update(&ptg_id, data);

  return 0;
}

static __always_inline int return_symlink(struct pt_regs *ctx) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }
  evt_syscall.delete(&ptg_id);

  mnt_dentry_addr.delete(&ptg_id);

  if (!rallied(ptg_id, 0x7)) {
    return 0;
  }

  // Ignore failed invocations
  if (PT_REGS_RC(ctx) != 0) {
    return 0;
  }

  // Copy mode
  //
  data->f_mode = 0;

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

// Kretprobe:
// int symlink(const char __user *oldname, const char __user *newname);
//
int return___syscall___symlink(struct pt_regs *ctx) { return return_symlink(ctx); }

// Kretprobe:
// int symlinkat(int olddfd, const char __user *oldname, int newdfd, const char __user
// *newname, int flags);
//
int return___syscall___symlinkat(struct pt_regs *ctx) { return return_symlink(ctx); }
