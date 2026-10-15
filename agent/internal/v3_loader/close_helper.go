package v3_loader

import (
	"errors"
	"os"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// closeEbpfObjects 反射关闭 objs 里所有 *ebpf.Program / *ebpf.Map 字段。
//
// 用于避免每个 loader 的 Close() 手写字段时漏关（BUG-033）。
// 只处理 *ebpf.Program 与 *ebpf.Map，其他类型跳过。
func closeEbpfObjects(objs any) {
	if objs == nil {
		return
	}
	v := reflect.ValueOf(objs)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}

	progType := reflect.TypeOf((*ebpf.Program)(nil))
	mapType := reflect.TypeOf((*ebpf.Map)(nil))
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		fv := v.Field(i)
		ft := t.Field(i).Type
		if !fv.CanInterface() {
			continue
		}

		switch ft {
		case progType:
			if fv.IsNil() {
				continue
			}
			if p, ok := fv.Interface().(*ebpf.Program); ok && p != nil {
				_ = p.Close()
			}
		case mapType:
			if fv.IsNil() {
				continue
			}
			if m, ok := fv.Interface().(*ebpf.Map); ok && m != nil {
				_ = m.Close()
			}
		}
	}
}

// isReaderClosed 判断 ringbuf.Read 返回的错误是否表示 reader 已关闭。
//
// 背景：Reader.Close() 之后阻塞中的 Read 不一定返回 ringbuf.ErrClosed，
// 也可能是 EBADF（epoll fd 被关）或 os.ErrClosed。
// 只判 ringbuf.ErrClosed 会让 goroutine 陷入「Read 失败 → log → continue」
// 的死循环（打日志刷屏 + goroutine 永不退出）。
func isReaderClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return true
	}
	if errors.Is(err, unix.EBADF) {
		return true
	}
	return false
}

// isReaderTimeout 判断 Read 错误是否是 deadline 超时。
//
// 背景：goroutine 每轮给 Read 设置 500ms deadline，让 Read 周期性返回，
// 以便检查 closed 标志。超时不是错误，应 continue 而非 return。
func isReaderTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if errors.Is(err, unix.ETIMEDOUT) {
		return true
	}
	return false
}
