package context

type ctxKey string

const (
	// CtxKeyDialer is the context key for the proxy dialer
	CtxKeyDialer ctxKey = "proxy_dialer"
)
