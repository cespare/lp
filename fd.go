package main

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const blockSize = 4096

// direntCount reads directory entries from the directory pointed at by f and
// returns the total count (non-recursively). The provided buffer is used for
// scratch space, if it's large enough; the final buffer is returned for later
// reuse in a subsequent call to this function.
//
// This function is equivalent to calling f.Readdirnames and taking the length
// of the result, but is more efficient because it avoids allocating space for
// the names (or indeed, inspecting the filenames at all).
func direntCount(f *os.File, b []byte) (int64, []byte, error) {
	var i, end int
	for {
		if len(b)-i < blockSize {
			// Buffer to getdents needs to be at least a block.
			// Linear growth is okay because we're going to reuse
			// the buffer in future calls.
			b1 := make([]byte, len(b)+blockSize)
			copy(b1, b)
			b = b1
		}
		n, errno := unix.ReadDirent(int(f.Fd()), b[i:])
		// KeepAlive is used to ensure that f stays alive during the
		// ReadDirent call (since we're passing the fd as an integer).
		// It's not strictly necessary here because of the surrounding
		// loop, but we'll stick to the standard syscall pattern to
		// avoid making the reader reason about it.
		runtime.KeepAlive(f)
		if errno != nil {
			return 0, b, wrapSyscallError("readdirent", errno)
		}
		if n <= 0 {
			break // EOF
		}
		i += n
		end += n
	}
	var count int64
	for buf := b[:end]; len(buf) > 0; {
		reclen, ok := direntReclen(buf)
		if !ok || reclen > uint64(len(buf)) {
			break
		}
		rec := buf[:reclen]
		buf = buf[reclen:]
		ino, ok := direntIno(rec)
		if !ok {
			break
		}
		if ino == 0 {
			continue // File absent in directory.
		}
		count++
	}
	// We didn't look at directory names at all in the above loop, so we
	// need to subtract two to account for the . and .. entries.
	return count - 2, b, nil
}

func wrapSyscallError(name string, err error) error {
	if _, ok := err.(syscall.Errno); ok {
		err = os.NewSyscallError(name, err)
	}
	return err
}

func direntReclen(buf []byte) (uint64, bool) {
	return readInt(
		buf,
		unsafe.Offsetof(unix.Dirent{}.Reclen),
		unsafe.Sizeof(unix.Dirent{}.Reclen),
	)
}

func direntIno(buf []byte) (uint64, bool) {
	return readInt(
		buf,
		unsafe.Offsetof(unix.Dirent{}.Ino),
		unsafe.Sizeof(unix.Dirent{}.Ino),
	)
}

func readInt(b []byte, off, size uintptr) (uint64, bool) {
	if len(b) < int(off+size) {
		return 0, false
	}
	b = b[off:]
	switch size {
	case 1:
		return uint64(b[0]), true
	case 2:
		_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
		return uint64(b[0]) | uint64(b[1])<<8, true
	case 4:
		_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
		return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24, true
	case 8:
		_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
		return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56, true
	default:
		panic("readInt with unsupported size")
	}
}
