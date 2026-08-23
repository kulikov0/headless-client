//go:build unix

package headlessclient

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestChromeDialerLeavesTCPKeepAliveOff(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		accepted, acceptErr := listener.Accept()
		if acceptErr == nil {
			defer accepted.Close()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := chromeDialer().DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer connection.Close()

	rawConn, err := connection.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}

	var keepAlive int
	var optErr error
	if controlErr := rawConn.Control(func(descriptor uintptr) {
		keepAlive, optErr = syscall.GetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	}); controlErr != nil {
		t.Fatalf("control: %v", controlErr)
	}
	if optErr != nil {
		t.Fatalf("getsockopt SO_KEEPALIVE: %v", optErr)
	}
	if keepAlive != 0 {
		t.Fatalf("SO_KEEPALIVE = %d, want 0; a zero net.Dialer.KeepAlive turns on a 15 second probe metronome that chrome never emits", keepAlive)
	}
}

func TestDefaultDialerWouldEnableTheKeepAliveMetronome(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		accepted, acceptErr := listener.Accept()
		if acceptErr == nil {
			defer accepted.Close()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer connection.Close()

	rawConn, err := connection.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}

	var keepAlive int
	if controlErr := rawConn.Control(func(descriptor uintptr) {
		keepAlive, _ = syscall.GetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	}); controlErr != nil {
		t.Fatalf("control: %v", controlErr)
	}
	if keepAlive == 0 {
		t.Skip("this platform does not honour the go default keep alive, so chromeDialer has nothing to suppress here")
	}
}
