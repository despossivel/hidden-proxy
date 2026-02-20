package proxy

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	redis "github.com/redis/go-redis/v9"
	"golang.org/x/net/html"
	torClient "tor-onion-proxy/tor"
)

type ReverseProxy struct {
	targetOnion string
	proxyOnion  string
	client      *http.Client
	cache       *responseCache
}

func New(targetOnion, proxyOnion, socksAddr string) (*ReverseProxy, error) {
	client, err := torClient.NewHTTPClient(socksAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create tor client: %w", err)
	}

	// Cache size & TTL configurable via env for resource-constrained devices.
	cacheBytes := int64(10 * 1024 * 1024) // default 10 MB (RPi-friendly)
	if v := os.Getenv("CACHE_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cacheBytes = n
		}
	}
	cacheTTL := 60 * time.Second
	if v := os.Getenv("CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cacheTTL = d
		}
	}

	return &ReverseProxy{
		targetOnion: strings.TrimRight(targetOnion, "/"),
		proxyOnion:  strings.TrimRight(proxyOnion, "/"),
		client:      client,
		cache:       newResponseCache(cacheBytes, cacheTTL),
	}, nil
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// serve from cache for GETs when available
	if r.Method == http.MethodGet {
		if ent := p.cache.get(r.URL.String()); ent != nil {
			// write cached headers and body
			for k, vals := range ent.hdr {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			// ensure CORS headers are present
			if p.proxyOnion != "" {
				p.setCORSHeaders(w.Header(), r)
			}
			w.WriteHeader(ent.status)
			_, _ = w.Write(ent.body)
			log.Printf("CACHE %s %s → %d (%d bytes) in %v", r.Method, r.RequestURI, ent.status, len(ent.body), time.Since(start))
			return
		}
	}

	// respond to CORS preflight immediately without forwarding to the app
	if r.Method == http.MethodOptions {
		p.setCORSHeaders(w.Header(), r)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// build the target URL — replace the host with the real app .onion
	targetURL := fmt.Sprintf("http://%s%s", p.targetOnion, r.RequestURI)

	// create the request to the upstream app
	outReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}

	// copy original headers
	copyHeaders(outReq.Header, r.Header)

	// remove headers that could expose proxy information
	outReq.Header.Del("X-Forwarded-For")
	outReq.Header.Del("X-Real-IP")
	outReq.Header.Set("Host", p.targetOnion)

	// CRITICAL: force upstream to send uncompressed so we can reliably
	// search and replace target onion references in the body.
	outReq.Header.Set("Accept-Encoding", "identity")

	// forward the request to the app via Tor
	resp, err := p.client.Do(outReq)
	if err != nil {
		log.Printf("failed to contact upstream app: %v", err)
		http.Error(w, "upstream app unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// copy response headers, rewriting Location to avoid leaking the app's .onion
	copyHeaders(w.Header(), resp.Header)
	if p.proxyOnion != "" {
		p.rewriteLocationHeader(w.Header())
		p.setCORSHeaders(w.Header(), r)
		p.rewriteCSPHeaders(w.Header())
		p.rewriteSetCookieHeaders(w.Header())
	}

	// Remove upstream Content-Encoding — we forced identity on the request,
	// but the server might still send gzip. Either way, WE control encoding
	// to the client from here.
	upstreamEnc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	w.Header().Del("Content-Encoding")
	w.Header().Del("Content-Length") // will be recalculated

	// rewrite textual response bodies to replace references to the app's .onion
	contentType := resp.Header.Get("Content-Type")
	shouldRewrite := p.proxyOnion != "" && isTextualContentType(contentType)

	var written int64
	if shouldRewrite {
		// avoid rewriting very large bodies — stream them instead
		// 2 MB cap keeps peak RSS low on RPi (was 5 MB)
		const maxRewriteSize = 2 * 1024 * 1024 // 2 MB
		if resp.ContentLength > maxRewriteSize && resp.ContentLength > 0 {
			w.WriteHeader(resp.StatusCode)
			var err error
			written, err = io.Copy(w, resp.Body)
			if err != nil {
				log.Printf("error streaming large response: %v", err)
			}
		} else {
			// read body, decompressing if upstream ignored our identity request
			body, err := readResponseBody(resp.Body, upstreamEnc)
			if err != nil {
				log.Printf("error reading body: %v", err)
				w.WriteHeader(http.StatusBadGateway)
			} else {
				// rewrite target onion → proxy onion
				if bytes.Contains(body, []byte(p.targetOnion)) {
					if strings.Contains(contentType, "text/html") {
						body = p.rewriteHTML(body)
					} else {
						body = p.rewriteBody(body)
					}
				}

				// compress for client if accepted
				clientAcceptsGzip := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
				if clientAcceptsGzip && len(body) > 256 {
					var buf bytes.Buffer
					// BestSpeed (level 1) → 3-5x less CPU than default, ~10 % bigger output.
					// On RPi this matters more than bandwidth.
					gz, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
					_, _ = gz.Write(body)
					_ = gz.Close()
					w.Header().Set("Content-Encoding", "gzip")
					w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
					w.WriteHeader(resp.StatusCode)
					n, _ := w.Write(buf.Bytes())
					written = int64(n)
				} else {
					w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
					w.WriteHeader(resp.StatusCode)
					n, _ := w.Write(body)
					written = int64(n)
				}

				// cache small cacheable GET responses (store uncompressed)
				if r.Method == http.MethodGet && resp.StatusCode == http.StatusOK {
					if int64(len(body)) <= 1*1024*1024 {
						p.cache.set(r.URL.String(), w.Header(), body, resp.StatusCode)
					}
				}
			}
		}
	} else {
		// binary / non-text: stream through unchanged
		w.WriteHeader(resp.StatusCode)
		var err error
		written, err = io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("error streaming response: %v", err)
		}
	}

	log.Printf("%s %s → %d (%d bytes) in %v",
		r.Method, r.RequestURI, resp.StatusCode, written, time.Since(start))
}

// setCORSHeaders injects the correct CORS headers, using the proxy .onion as the allowed origin.
func (p *ReverseProxy) setCORSHeaders(h http.Header, r *http.Request) {
	proxyOrigin := "http://" + p.proxyOnion

	// allow only the proxy origin; replaces any value coming from the app
	h.Set("Access-Control-Allow-Origin", proxyOrigin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Vary", "Origin")

	// on preflight, echo back the requested methods and headers
	if r.Method == http.MethodOptions {
		reqMethod := r.Header.Get("Access-Control-Request-Method")
		if reqMethod == "" {
			reqMethod = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
		}
		h.Set("Access-Control-Allow-Methods", reqMethod)

		reqHeaders := r.Header.Get("Access-Control-Request-Headers")
		if reqHeaders != "" {
			h.Set("Access-Control-Allow-Headers", reqHeaders)
		} else {
			h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		}
		h.Set("Access-Control-Max-Age", "86400")
	}
}

// rewriteLocationHeader replaces the app .onion host with the proxy .onion in Location and Refresh headers.
func (p *ReverseProxy) rewriteLocationHeader(h http.Header) {
	for _, key := range []string{"Location", "Refresh", "Content-Location"} {
		if val := h.Get(key); val != "" {
			h.Set(key, strings.ReplaceAll(val, p.targetOnion, p.proxyOnion))
		}
	}
}

// rewriteBody replaces all occurrences of the app .onion with the proxy .onion.
func (p *ReverseProxy) rewriteBody(body []byte) []byte {
	return bytes.ReplaceAll(body, []byte(p.targetOnion), []byte(p.proxyOnion))
}

// rewriteHTML parses HTML and rewrites href/src/action attributes, <base> tags,
// and inline script content to replace target onion with proxy onion.
func (p *ReverseProxy) rewriteHTML(body []byte) []byte {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return p.rewriteBody(body)
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// rewrite <base href> to proxy origin
			if n.Data == "base" {
				for i, a := range n.Attr {
					if strings.EqualFold(a.Key, "href") {
						if strings.Contains(a.Val, p.targetOnion) {
							n.Attr[i].Val = strings.ReplaceAll(a.Val, p.targetOnion, p.proxyOnion)
						}
					}
				}
			}

			// rewrite href, src, action, data, poster, srcset attributes
			rewriteAttrs := map[string]bool{"href": true, "src": true, "action": true, "data": true, "poster": true, "srcset": true, "content": true}
			for i, a := range n.Attr {
				if rewriteAttrs[strings.ToLower(a.Key)] && strings.Contains(a.Val, p.targetOnion) {
					n.Attr[i].Val = strings.ReplaceAll(a.Val, p.targetOnion, p.proxyOnion)
				}
			}

			// rewrite inline <script> bodies
			if n.Data == "script" || n.Data == "style" {
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode && strings.Contains(c.Data, p.targetOnion) {
						c.Data = strings.ReplaceAll(c.Data, p.targetOnion, p.proxyOnion)
					}
				}
			}
		}

		// also rewrite plain text nodes that might contain the target (e.g., inside <noscript>)
		if n.Type == html.TextNode && strings.Contains(n.Data, p.targetOnion) {
			n.Data = strings.ReplaceAll(n.Data, p.targetOnion, p.proxyOnion)
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		return p.rewriteBody(body)
	}
	return buf.Bytes()
}

// readResponseBody reads the full response body, decompressing gzip if needed.
func readResponseBody(body io.Reader, encoding string) ([]byte, error) {
	if encoding == "gzip" {
		gr, err := gzip.NewReader(body)
		if err != nil {
			// fallback: read raw
			return io.ReadAll(body)
		}
		defer gr.Close()
		return io.ReadAll(gr)
	}
	return io.ReadAll(body)
}

// isTextualContentType returns true for content types where we should rewrite the body.
func isTextualContentType(ct string) bool {
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "text/css") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "text/plain") ||
		strings.Contains(ct, "text/xml") ||
		strings.Contains(ct, "application/xml") ||
		strings.Contains(ct, "application/xhtml")
}

// rewriteCSPHeaders replaces occurrences of the target onion with the proxy onion
// and loosens CSP to allow common external font sources and data: for media.
func (p *ReverseProxy) rewriteCSPHeaders(h http.Header) {
	for _, headerName := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		if csp := h.Get(headerName); csp != "" {
			new := strings.ReplaceAll(csp, p.targetOnion, p.proxyOnion)

			// ensure media-src allows data:
			if strings.Contains(new, "media-src") {
				new = strings.ReplaceAll(new, "media-src", "media-src data:")
			} else {
				// append media-src data: if absent
				new = new + "; media-src data:"
			}

			// ensure style-src allows Google Fonts and proxy origin
			if strings.Contains(new, "style-src") {
				new = strings.ReplaceAll(new, "style-src", "style-src https://fonts.googleapis.com https://fonts.gstatic.com http://"+p.proxyOnion)
			} else {
				new = new + "; style-src https://fonts.googleapis.com https://fonts.gstatic.com http://" + p.proxyOnion
			}

			// also allow targetOnion in style-src to avoid blocking when absolute URLs remain
			if !strings.Contains(new, p.targetOnion) {
				new = strings.ReplaceAll(new, "style-src", "style-src http://"+p.targetOnion)
			}

			// ensure font-src allows Google fonts
			if strings.Contains(new, "font-src") {
				new = strings.ReplaceAll(new, "font-src", "font-src https://fonts.gstatic.com http://"+p.proxyOnion)
			} else {
				new = new + "; font-src https://fonts.gstatic.com http://" + p.proxyOnion
			}

			// ensure script-src allows inline scripts (fallback) and proxy origin
			if strings.Contains(new, "script-src") {
				new = strings.ReplaceAll(new, "script-src", "script-src http://"+p.proxyOnion+" 'unsafe-inline'")
			} else {
				new = new + "; script-src http://" + p.proxyOnion + " 'unsafe-inline'"
			}

			h.Set(headerName, new)
		}
	}
}

// rewriteSetCookieHeaders rewrites Set-Cookie headers to remove Domain (so cookie becomes host-only)
// and ensures SameSite=None and Secure to allow cross-site usage via the proxy origin.
func (p *ReverseProxy) rewriteSetCookieHeaders(h http.Header) {
	vals := h.Values("Set-Cookie")
	if len(vals) == 0 {
		return
	}
	newVals := make([]string, 0, len(vals))
	for _, v := range vals {
		parts := strings.Split(v, ";")
		keep := make([]string, 0, len(parts))
		for _, part := range parts {
			ppart := strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(ppart), "domain=") {
				// drop Domain to make cookie host-only (proxy will set it)
				continue
			}
			if strings.EqualFold(ppart, "samesite=strict") || strings.EqualFold(ppart, "samesite=lax") {
				// replace with None
				continue
			}
			keep = append(keep, ppart)
		}
		// ensure SameSite=None and Secure
		keep = append(keep, "SameSite=None", "Secure")
		newVals = append(newVals, strings.Join(keep, "; "))
	}
	h.Del("Set-Cookie")
	for _, nv := range newVals {
		h.Add("Set-Cookie", nv)
	}
}

// --- simple LRU cache for responses ---
type cacheEntry struct {
	key    string
	hdr    http.Header
	body   []byte
	status int
	expiry time.Time
	size   int64
}

type responseCache struct {
	mu       sync.Mutex
	ll       *list.List
	items    map[string]*list.Element
	maxBytes int64
	curBytes int64
	ttl      time.Duration
	// optional Redis client
	redisClient *redis.Client
	ctx         context.Context
}

func newResponseCache(maxBytes int64, ttl time.Duration) *responseCache {
	rc := &responseCache{
		ll:       list.New(),
		items:    make(map[string]*list.Element),
		maxBytes: maxBytes,
		ttl:      ttl,
	}

	// optional Redis backing if REDIS_ADDR is provided
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		opt := &redis.Options{Addr: addr}
		client := redis.NewClient(opt)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := client.Ping(ctx).Err(); err == nil {
			rc.redisClient = client
			rc.ctx = context.Background()
			log.Printf("response cache: using Redis at %s", addr)
		} else {
			log.Printf("response cache: cannot connect to Redis at %s: %v", addr, err)
		}
	}

	return rc
}

func (c *responseCache) get(key string) *cacheEntry {
	// if Redis is enabled, try Redis first
	if c.redisClient != nil {
		val, err := c.redisClient.Get(c.ctx, key).Result()
		if err == nil {
			var obj struct {
				Hdr    map[string][]string `json:"hdr"`
				Body   string              `json:"body"`
				Status int                 `json:"status"`
				Expiry int64               `json:"expiry"`
			}
			if err := json.Unmarshal([]byte(val), &obj); err == nil {
				if time.Now().Unix() > obj.Expiry {
					c.redisClient.Del(c.ctx, key)
				} else {
					body, _ := base64.StdEncoding.DecodeString(obj.Body)
					return &cacheEntry{key: key, hdr: cloneHeader(obj.Hdr), body: body, status: obj.Status, expiry: time.Unix(obj.Expiry, 0), size: int64(len(body))}
				}
			}
		}
		// fall back to memory
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		ent := el.Value.(*cacheEntry)
		if time.Now().After(ent.expiry) {
			c.removeElement(el)
			return nil
		}
		c.ll.MoveToFront(el)
		return ent
	}
	return nil
}

func (c *responseCache) set(key string, hdr http.Header, body []byte, status int) {
	// if Redis is enabled, store in Redis
	if c.redisClient != nil {
		obj := struct {
			Hdr    map[string][]string `json:"hdr"`
			Body   string              `json:"body"`
			Status int                 `json:"status"`
			Expiry int64               `json:"expiry"`
		}{
			Hdr:    cloneHeader(hdr),
			Body:   base64.StdEncoding.EncodeToString(body),
			Status: status,
			Expiry: time.Now().Add(c.ttl).Unix(),
		}
		if b, err := json.Marshal(&obj); err == nil {
			_ = c.redisClient.Set(c.ctx, key, string(b), c.ttl).Err()
		}
		// still store in-memory for fast access
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.removeElement(el)
	}
	ent := &cacheEntry{
		key:    key,
		hdr:    cloneHeader(hdr),
		body:   append([]byte(nil), body...),
		status: status,
		expiry: time.Now().Add(c.ttl),
		size:   int64(len(body)),
	}
	el := c.ll.PushFront(ent)
	c.items[key] = el
	c.curBytes += ent.size
	for c.curBytes > c.maxBytes {
		// evict
		last := c.ll.Back()
		if last == nil {
			break
		}
		c.removeElement(last)
	}
}

func (c *responseCache) removeElement(el *list.Element) {
	ent := el.Value.(*cacheEntry)
	delete(c.items, ent.key)
	c.ll.Remove(el)
	c.curBytes -= ent.size
}

func cloneHeader(h http.Header) http.Header {
	nh := make(http.Header, len(h))
	for k, vv := range h {
		vvc := make([]string, len(vv))
		copy(vvc, vv)
		nh[k] = vvc
	}
	return nh
}

func copyHeaders(dst, src http.Header) {
	// skip Content-Length since the body may be rewritten (will be recalculated)
	src.Del("Content-Length")
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
