package anytls

// 魔改 #3: AnyTLS 认证失败兜底 -> 进程内 HTTP 反向代理到一个真实站,
// 让主动探测看到一个正常 HTTPS 网站, 增强抗主动探测。
// 注意: 只有"认证失败"的连接(探测器/扫描器)才会走到这里; 真实用户认证通过后永不经过,
// 因此对真实用户的速度/并发零影响。连接在进入这里前已由 sing-anytls 还原为完整原始字节流。

import (
	"context"
	"errors"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type anytlsFallback struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
	logger logger.ContextLogger
}

func newAnytlsFallback(rawURL string, logger logger.ContextLogger) (*anytlsFallback, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("anytls fallback: invalid url: " + rawURL)
	}
	f := &anytlsFallback{target: u, logger: logger}
	proxy := httputil.NewSingleHostReverseProxy(u)
	orig := proxy.Director
	proxy.Director = func(req *http.Request) {
		orig(req)         // 设 scheme/host, 并把 target.Path(如 /en) 前缀拼到请求路径
		req.Host = u.Host // 关键: 让上游收到正确 Host / TLS SNI
	}
	// 上游不可达时静默 502, 不刷屏
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusBadGateway)
	}
	f.proxy = proxy
	return f, nil
}

func (f *anytlsFallback) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	f.logger.DebugContext(ctx, "anytls fallback from ", source, " -> ", f.target.Host)
	// 在这条已还原完整字节流的连接上跑一次性 HTTP server, 用反代 handler 处理。
	l := newOneConnListener(conn)
	srv := &http.Server{
		Handler:      f.proxy,
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  20 * time.Second,
		ErrorLog:     stdlog.New(io.Discard, "", 0), // 静默探测器的畸形请求, 不刷 stderr
	}
	_ = srv.Serve(l) // 阻塞直到连接关闭
	if onClose != nil {
		onClose(nil)
	}
}

// ---- 单连接监听器: 让 http.Server 在一条已有 net.Conn 上服务 ----

var errFallbackListenerClosed = errors.New("anytls fallback listener closed")

type oneConnListener struct {
	ch   chan net.Conn
	addr net.Addr
	once sync.Once
}

func newOneConnListener(conn net.Conn) *oneConnListener {
	l := &oneConnListener{ch: make(chan net.Conn, 1), addr: conn.LocalAddr()}
	l.ch <- &closeNotifyConn{Conn: conn, l: l}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, errFallbackListenerClosed
	}
	return c, nil
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.ch) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr {
	if l.addr != nil {
		return l.addr
	}
	return &net.TCPAddr{}
}

// closeNotifyConn 在底层连接关闭时同时关闭 listener, 使 http.Server.Serve 退出, 避免 goroutine 泄漏。
type closeNotifyConn struct {
	net.Conn
	l    *oneConnListener
	once sync.Once
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(func() { c.l.Close() })
	return c.Conn.Close()
}
