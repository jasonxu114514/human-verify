package captcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "image/jpeg"
)

type Config struct {
	AssetsDir           string
	AssetURLPrefix      string
	Width               int
	Height              int
	PieceSize           int
	SessionTTL          time.Duration
	AttemptCookieSecret string
	PowDifficulty       int
}

type Service struct {
	cfg                 Config
	assets              []asset
	attemptCookieSecret []byte
	mu                  sync.Mutex
	sessions            map[string]*session
}

type asset struct {
	Name  string
	Image *image.RGBA
}

type session struct {
	Token         string
	AssetName     string
	TargetX       int
	PieceY        int
	AttemptMarker string
	ProofNonce    string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type challengeResponse struct {
	Token         string `json:"token"`
	PanelURL      string `json:"panelUrl"`
	PieceURL      string `json:"pieceUrl"`
	ProofNonce    string `json:"proofNonce"`
	PowDifficulty int    `json:"powDifficulty"`
	Width         int    `json:"width"`
	Height        int    `json:"height"`
	PieceSize     int    `json:"pieceSize"`
	PieceY        int    `json:"pieceY"`
	SliderMax     int    `json:"sliderMax"`
	ExpiresInMS   int64  `json:"expiresInMs"`
	AttemptMarker string `json:"-"`
}

type verifyRequest struct {
	Token         string        `json:"token"`
	SliderX       float64       `json:"sliderX"`
	DurationMS    int64         `json:"durationMs"`
	Trace         []tracePoint  `json:"trace"`
	PowCounter    int64         `json:"powCounter"`
	PowDigest     string        `json:"powDigest"`
	Proof         string        `json:"proof"`
	ProofSalt     string        `json:"proofSalt"`
	ClientSignals clientSignals `json:"clientSignals"`
}

type tracePoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
	T int64   `json:"t"`
}

type verifyResponse struct {
	Success bool    `json:"success"`
	Score   float64 `json:"score"`
	Message string  `json:"message"`
}

type clientSignals struct {
	WebDriver           bool   `json:"webDriver"`
	UserAgent           string `json:"userAgent"`
	Language            string `json:"language"`
	Platform            string `json:"platform"`
	TimeZone            string `json:"timeZone"`
	HardwareConcurrency int    `json:"hardwareConcurrency"`
	DeviceMemory        int    `json:"deviceMemory"`
	ScreenWidth         int    `json:"screenWidth"`
	ScreenHeight        int    `json:"screenHeight"`
	ColorDepth          int    `json:"colorDepth"`
	CookieEnabled       bool   `json:"cookieEnabled"`
}

const attemptCookieName = "hv_attempt"

func NewService(cfg Config) (*Service, error) {
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.PieceSize <= 0 {
		return nil, fmt.Errorf("invalid captcha dimensions")
	}
	if cfg.AssetsDir == "" {
		return nil, fmt.Errorf("assets dir is required")
	}

	entries, err := os.ReadDir(cfg.AssetsDir)
	if err != nil {
		return nil, fmt.Errorf("read assets dir: %w", err)
	}

	assets := make([]asset, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		switch ext {
		case ".png", ".jpg", ".jpeg":
			panelImage, err := loadRasterAsset(filepath.Join(cfg.AssetsDir, entry.Name()), cfg.Width, cfg.Height)
			if err != nil {
				return nil, fmt.Errorf("load asset %s: %w", entry.Name(), err)
			}
			item := asset{
				Name:  entry.Name(),
				Image: panelImage,
			}
			assets = append(assets, item)
		}
	}
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].Name < assets[j].Name
	})
	if len(assets) == 0 {
		return nil, fmt.Errorf("no usable assets found in %s", cfg.AssetsDir)
	}
	if cfg.AssetURLPrefix == "" {
		cfg.AssetURLPrefix = "/static/assets/"
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 2 * time.Minute
	}
	if cfg.PowDifficulty <= 0 {
		cfg.PowDifficulty = 3
	}

	secret := []byte(cfg.AttemptCookieSecret)
	if len(secret) == 0 {
		var err error
		secret, err = randomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("generate attempt cookie secret: %w", err)
		}
	}

	return &Service{
		cfg:                 cfg,
		assets:              assets,
		attemptCookieSecret: secret,
		sessions:            make(map[string]*session),
	}, nil
}

func (s *Service) HandleNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	challenge, err := s.newChallenge()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.setAttemptCookie(w, challenge.AttemptMarker, s.cfg.SessionTTL)
	writeJSON(w, http.StatusOK, challenge)
}

func (s *Service) HandlePanel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := tokenFromPath("/api/captcha/panel/", r.URL.Path)
	if token == "" {
		http.NotFound(w, r)
		return
	}

	current, ok := s.getSession(token)
	if !ok {
		http.Error(w, "captcha challenge expired", http.StatusGone)
		return
	}

	writeNoCache(w)
	w.Header().Set("Content-Type", "image/png")
	imageData, err := s.renderPanelPNG(current)
	if err != nil {
		http.Error(w, "render panel failed", http.StatusInternalServerError)
		return
	}
	_ = png.Encode(w, imageData)
}

func (s *Service) HandlePiece(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := tokenFromPath("/api/captcha/piece/", r.URL.Path)
	if token == "" {
		http.NotFound(w, r)
		return
	}

	current, ok := s.getSession(token)
	if !ok {
		http.Error(w, "captcha challenge expired", http.StatusGone)
		return
	}

	writeNoCache(w)
	w.Header().Set("Content-Type", "image/png")
	imageData, err := s.renderPiecePNG(current)
	if err != nil {
		http.Error(w, "render piece failed", http.StatusInternalServerError)
		return
	}
	_ = png.Encode(w, imageData)
}

func (s *Service) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid verify payload", http.StatusBadRequest)
		return
	}

	current, ok := s.consumeSession(req.Token)
	if !ok {
		writeJSON(w, http.StatusGone, verifyResponse{
			Success: false,
			Score:   0,
			Message: "captcha challenge expired",
		})
		return
	}

	if ok, message := s.validateAttemptProof(r, current, req); !ok {
		clearAttemptCookie(w)
		writeJSON(w, http.StatusForbidden, verifyResponse{
			Success: false,
			Score:   0,
			Message: message,
		})
		return
	}

	success, score, message := s.evaluateTrajectory(current, req)
	clearAttemptCookie(w)
	writeJSON(w, http.StatusOK, verifyResponse{
		Success: success,
		Score:   round(score, 3),
		Message: message,
	})
}

func (s *Service) newChallenge() (*challengeResponse, error) {
	token, err := randomToken(18)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	attemptMarker, err := randomToken(16)
	if err != nil {
		return nil, fmt.Errorf("create attempt marker: %w", err)
	}
	proofNonce, err := randomToken(16)
	if err != nil {
		return nil, fmt.Errorf("create proof nonce: %w", err)
	}

	assetIndex, err := randomInt(len(s.assets))
	if err != nil {
		return nil, fmt.Errorf("pick asset: %w", err)
	}

	targetX, err := randomIntRange(72, s.cfg.Width-s.cfg.PieceSize-18)
	if err != nil {
		return nil, fmt.Errorf("pick target x: %w", err)
	}

	pieceY, err := randomIntRange(18, s.cfg.Height-s.cfg.PieceSize-18)
	if err != nil {
		return nil, fmt.Errorf("pick piece y: %w", err)
	}

	now := time.Now()
	current := &session{
		Token:         token,
		AssetName:     s.assets[assetIndex].Name,
		TargetX:       targetX,
		PieceY:        pieceY,
		AttemptMarker: attemptMarker,
		ProofNonce:    proofNonce,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.cfg.SessionTTL),
	}

	s.mu.Lock()
	s.cleanupLocked(now)
	s.sessions[token] = current
	s.mu.Unlock()

	return &challengeResponse{
		Token:         token,
		PanelURL:      fmt.Sprintf("/api/captcha/panel/%s.png", token),
		PieceURL:      fmt.Sprintf("/api/captcha/piece/%s.png", token),
		ProofNonce:    proofNonce,
		PowDifficulty: s.cfg.PowDifficulty,
		Width:         s.cfg.Width,
		Height:        s.cfg.Height,
		PieceSize:     s.cfg.PieceSize,
		PieceY:        pieceY,
		SliderMax:     s.cfg.Width - s.cfg.PieceSize,
		ExpiresInMS:   s.cfg.SessionTTL.Milliseconds(),
		AttemptMarker: attemptMarker,
	}, nil
}

func (s *Service) getSession(token string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(current.ExpiresAt) {
		delete(s.sessions, token)
		return nil, false
	}
	return current, true
}

func (s *Service) consumeSession(token string) (*session, bool) {
	if token == "" {
		return nil, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	delete(s.sessions, token)
	if time.Now().After(current.ExpiresAt) {
		return nil, false
	}
	return current, true
}

func (s *Service) cleanupLocked(now time.Time) {
	for token, current := range s.sessions {
		if now.After(current.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}

func (s *Service) renderPanelPNG(current *session) (*image.RGBA, error) {
	src, ok := s.assetImage(current.AssetName)
	if !ok {
		return nil, fmt.Errorf("asset not found")
	}

	dst := cloneRGBA(src)
	for y := 0; y < s.cfg.PieceSize; y++ {
		for x := 0; x < s.cfg.PieceSize; x++ {
			if !pointInPieceShape(x, y, s.cfg.PieceSize) {
				continue
			}
			px := current.TargetX + x
			py := current.PieceY + y
			base := dst.RGBAAt(px, py)
			if isPieceEdge(x, y, s.cfg.PieceSize) {
				dst.SetRGBA(px, py, color.RGBA{255, 255, 255, 255})
				continue
			}
			dst.SetRGBA(px, py, blendRGBA(base, color.RGBA{248, 251, 254, 255}, 224))
		}
	}

	return dst, nil
}

func (s *Service) renderPiecePNG(current *session) (*image.NRGBA, error) {
	src, ok := s.assetImage(current.AssetName)
	if !ok {
		return nil, fmt.Errorf("asset not found")
	}

	dst := image.NewNRGBA(image.Rect(0, 0, s.cfg.PieceSize, s.cfg.PieceSize))
	for y := 0; y < s.cfg.PieceSize; y++ {
		for x := 0; x < s.cfg.PieceSize; x++ {
			if !pointInPieceShape(x, y, s.cfg.PieceSize) {
				continue
			}
			base := src.RGBAAt(current.TargetX+x, current.PieceY+y)
			colorValue := color.NRGBA{R: base.R, G: base.G, B: base.B, A: 255}
			if isPieceEdge(x, y, s.cfg.PieceSize) {
				colorValue = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
			}
			dst.SetNRGBA(x, y, colorValue)
		}
	}

	return dst, nil
}

func (s *Service) evaluateTrajectory(current *session, req verifyRequest) (bool, float64, string) {
	sliderMax := float64(s.cfg.Width - s.cfg.PieceSize)
	if req.SliderX < 0 || req.SliderX > sliderMax {
		return false, 0, "slider distance out of range"
	}

	trace := sanitizeTrace(req.Trace, sliderMax)
	if len(trace) < 10 {
		return false, 0, "not enough trace points"
	}

	finalTime := trace[len(trace)-1].T
	if req.DurationMS > finalTime {
		finalTime = req.DurationMS
	}
	if finalTime < 600 || finalTime > 15000 {
		return false, 0, "drag duration abnormal"
	}

	expectedX := float64(current.TargetX)
	positionDelta := math.Abs(req.SliderX - expectedX)
	if positionDelta > 7.5 {
		return false, 0.15, "piece not aligned"
	}

	var (
		minX          = trace[0].X
		maxX          = trace[0].X
		minY          = trace[0].Y
		maxY          = trace[0].Y
		totalDistance float64
		nonDecreasing int
		maxBacktrack  float64
		pauses        int
	)

	xBuckets := map[int]struct{}{int(math.Round(trace[0].X / 4)): {}}
	speedSamples := make([]float64, 0, len(trace))

	for i := 1; i < len(trace); i++ {
		dx := trace[i].X - trace[i-1].X
		dy := trace[i].Y - trace[i-1].Y
		dt := trace[i].T - trace[i-1].T
		if dt <= 0 {
			continue
		}

		if trace[i].X < minX {
			minX = trace[i].X
		}
		if trace[i].X > maxX {
			maxX = trace[i].X
		}
		if trace[i].Y < minY {
			minY = trace[i].Y
		}
		if trace[i].Y > maxY {
			maxY = trace[i].Y
		}

		if dx >= -1 {
			nonDecreasing++
		}
		if dx < maxBacktrack {
			maxBacktrack = dx
		}
		if dt >= 90 {
			pauses++
		}

		totalDistance += math.Hypot(dx, dy)
		speedSamples = append(speedSamples, dx/float64(dt))
		xBuckets[int(math.Round(trace[i].X/4))] = struct{}{}
	}

	xSpan := maxX - minX
	ySpan := maxY - minY
	monoRatio := float64(nonDecreasing) / float64(max(1, len(trace)-1))
	speedStdDev := stddev(speedSamples)

	if maxBacktrack < -18 {
		return false, 0.18, "trace contains unrealistic backtrack"
	}
	if monoRatio < 0.72 {
		return false, 0.21, "trace is too erratic"
	}
	if xSpan < req.SliderX-14 || xSpan > req.SliderX+14 {
		return false, 0.26, "trace span mismatch"
	}
	if totalDistance < req.SliderX*0.98 {
		return false, 0.24, "trace distance is too short"
	}
	if ySpan > 90 {
		return false, 0.20, "vertical movement abnormal"
	}
	if speedStdDev < 0.006 {
		return false, 0.23, "trace speed too uniform"
	}

	score := 0.0
	score += 0.42 - math.Min(positionDelta, 12)/40

	switch {
	case finalTime >= 900 && finalTime <= 6000:
		score += 0.14
	case finalTime >= 600 && finalTime <= 12000:
		score += 0.08
	}

	switch {
	case len(trace) >= 20:
		score += 0.08
	case len(trace) >= 12:
		score += 0.04
	}

	switch {
	case monoRatio >= 0.92:
		score += 0.10
	case monoRatio >= 0.84:
		score += 0.07
	case monoRatio >= 0.76:
		score += 0.04
	}

	switch {
	case ySpan >= 1.2 && ySpan <= 32:
		score += 0.07
	case ySpan >= 0.6 && ySpan <= 48:
		score += 0.04
	}

	switch {
	case totalDistance >= req.SliderX*1.06:
		score += 0.07
	case totalDistance >= req.SliderX*1.02:
		score += 0.04
	}

	switch {
	case len(xBuckets) >= 12:
		score += 0.05
	case len(xBuckets) >= 8:
		score += 0.03
	}

	switch {
	case speedStdDev >= 0.03:
		score += 0.09
	case speedStdDev >= 0.015:
		score += 0.05
	}

	if pauses >= 1 && pauses <= 8 {
		score += 0.04
	}

	if score < 0.72 {
		return false, score, "behavior score too low"
	}
	return true, score, "ok"
}

func (s *Service) validateAttemptProof(r *http.Request, current *session, req verifyRequest) (bool, string) {
	rawCookieValue, attemptMarker, ok := s.readSignedAttemptCookie(r)
	if !ok || attemptMarker == "" {
		return false, "attempt marker missing"
	}
	if attemptMarker != current.AttemptMarker {
		return false, "attempt marker mismatch"
	}
	if req.ClientSignals.WebDriver {
		return false, "webdriver detected"
	}
	if !req.ClientSignals.CookieEnabled {
		return false, "cookies disabled"
	}
	if req.ClientSignals.UserAgent == "" || req.ClientSignals.TimeZone == "" {
		return false, "client signals incomplete"
	}
	if req.ClientSignals.UserAgent != r.UserAgent() {
		return false, "user agent mismatch"
	}
	if len(req.ProofSalt) < 16 || len(req.Proof) != 64 {
		return false, "invalid js proof"
	}
	if len(req.PowDigest) != 64 || req.PowCounter < 0 {
		return false, "invalid pow payload"
	}

	trace := sanitizeTrace(req.Trace, float64(s.cfg.Width-s.cfg.PieceSize))
	if len(trace) < 4 {
		return false, "insufficient proof trace"
	}

	expectedPowDigest := buildPowDigest(current, rawCookieValue, req.ProofSalt, req.PowCounter)
	if !strings.EqualFold(req.PowDigest, expectedPowDigest) {
		return false, "pow digest mismatch"
	}
	if !hasLeadingHexZeros(expectedPowDigest, s.cfg.PowDifficulty) {
		return false, "pow too weak"
	}

	expectedProof := buildClientProof(current, rawCookieValue, req, trace)
	if !strings.EqualFold(req.Proof, expectedProof) {
		return false, "js proof mismatch"
	}
	return true, "ok"
}

func (s *Service) assetImage(assetName string) (*image.RGBA, bool) {
	for _, item := range s.assets {
		if item.Name == assetName && item.Image != nil {
			return item.Image, true
		}
	}
	return nil, false
}

func buildClientProof(current *session, signedAttemptCookie string, req verifyRequest, trace []tracePoint) string {
	traceDigest := traceDigestHex(trace)
	payload := strings.Join([]string{
		current.Token,
		current.ProofNonce,
		signedAttemptCookie,
		req.ProofSalt,
		strconv.FormatInt(req.PowCounter, 10),
		req.PowDigest,
		formatProofFloat(req.SliderX),
		strconv.FormatInt(req.DurationMS, 10),
		traceDigest,
		req.ClientSignals.UserAgent,
		req.ClientSignals.Language,
		req.ClientSignals.Platform,
		req.ClientSignals.TimeZone,
		strconv.Itoa(req.ClientSignals.HardwareConcurrency),
		strconv.Itoa(req.ClientSignals.DeviceMemory),
		strconv.Itoa(req.ClientSignals.ScreenWidth),
		strconv.Itoa(req.ClientSignals.ScreenHeight),
		strconv.Itoa(req.ClientSignals.ColorDepth),
		strconv.FormatBool(req.ClientSignals.CookieEnabled),
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func buildPowDigest(current *session, signedAttemptCookie, proofSalt string, powCounter int64) string {
	payload := strings.Join([]string{
		current.Token,
		current.ProofNonce,
		signedAttemptCookie,
		proofSalt,
		strconv.FormatInt(powCounter, 10),
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func hasLeadingHexZeros(value string, count int) bool {
	if count <= 0 {
		return true
	}
	if len(value) < count {
		return false
	}
	for i := 0; i < count; i++ {
		if value[i] != '0' {
			return false
		}
	}
	return true
}

func traceDigestHex(trace []tracePoint) string {
	var builder strings.Builder
	for index, point := range trace {
		if index > 0 {
			builder.WriteByte(';')
		}
		builder.WriteString(formatProofFloat(point.X))
		builder.WriteByte(',')
		builder.WriteString(formatProofFloat(point.Y))
		builder.WriteByte(',')
		builder.WriteString(strconv.FormatInt(point.T, 10))
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func formatProofFloat(value float64) string {
	return strconv.FormatFloat(round(value, 2), 'f', 2, 64)
}

func (s *Service) setAttemptCookie(w http.ResponseWriter, marker string, ttl time.Duration) {
	expiresAt := time.Now().Add(ttl).Unix()
	signedValue := s.signAttemptCookieValue(marker, expiresAt)
	http.SetCookie(w, &http.Cookie{
		Name:     attemptCookieName,
		Value:    signedValue,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
		Expires:  time.Unix(expiresAt, 0),
	})
}

func clearAttemptCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     attemptCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (s *Service) readSignedAttemptCookie(r *http.Request) (string, string, bool) {
	cookie, err := r.Cookie(attemptCookieName)
	if err != nil || cookie.Value == "" {
		return "", "", false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 {
		return "", "", false
	}
	expiresAt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > expiresAt {
		return "", "", false
	}
	expectedSignature := s.signAttemptCookieParts(parts[0], expiresAt)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
		return "", "", false
	}
	return cookie.Value, parts[0], true
}

func (s *Service) signAttemptCookieValue(marker string, expiresAt int64) string {
	return marker + "." + strconv.FormatInt(expiresAt, 10) + "." + s.signAttemptCookieParts(marker, expiresAt)
}

func (s *Service) signAttemptCookieParts(marker string, expiresAt int64) string {
	mac := hmac.New(sha256.New, s.attemptCookieSecret)
	mac.Write([]byte(marker))
	mac.Write([]byte("|"))
	mac.Write([]byte(strconv.FormatInt(expiresAt, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func pointInPieceShape(x, y, size int) bool {
	fx := float64(x) + 0.5
	fy := float64(y) + 0.5
	unit := float64(size) / 54.0
	left := 8 * unit
	top := 8 * unit
	body := 38 * unit
	radius := 8 * unit
	right := left + body
	bottom := top + body

	inRect := fx >= left && fx <= right && fy >= top && fy <= bottom
	inTopBump := distanceSquared(fx, fy, left+body/2, top) <= radius*radius
	inRightNotch := distanceSquared(fx, fy, right, top+body/2) <= radius*radius

	return (inRect || inTopBump) && !inRightNotch
}

func isPieceEdge(x, y, size int) bool {
	if !pointInPieceShape(x, y, size) {
		return false
	}
	for dy := -1; dy <= 1; dy++ {
		for dx := -1; dx <= 1; dx++ {
			if dx == 0 && dy == 0 {
				continue
			}
			if !pointInPieceShape(x+dx, y+dy, size) {
				return true
			}
		}
	}
	return false
}

func distanceSquared(x1, y1, x2, y2 float64) float64 {
	dx := x1 - x2
	dy := y1 - y2
	return dx*dx + dy*dy
}

func cloneRGBA(src *image.RGBA) *image.RGBA {
	dst := image.NewRGBA(src.Bounds())
	draw.Draw(dst, dst.Bounds(), src, src.Bounds().Min, draw.Src)
	return dst
}

func blendRGBA(base color.RGBA, overlay color.RGBA, alpha uint8) color.RGBA {
	a := int(alpha)
	inv := 255 - a
	return color.RGBA{
		R: uint8((int(base.R)*inv + int(overlay.R)*a) / 255),
		G: uint8((int(base.G)*inv + int(overlay.G)*a) / 255),
		B: uint8((int(base.B)*inv + int(overlay.B)*a) / 255),
		A: 255,
	}
}

func loadRasterAsset(fullPath string, width, height int) (*image.RGBA, error) {
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	src, _, err := image.Decode(file)
	if err != nil {
		return nil, err
	}
	return scaleToRGBA(src, width, height), nil
}

func scaleToRGBA(src image.Image, width, height int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	bounds := src.Bounds()
	srcW := bounds.Dx()
	srcH := bounds.Dy()
	for y := 0; y < height; y++ {
		sy := bounds.Min.Y + y*srcH/height
		for x := 0; x < width; x++ {
			sx := bounds.Min.X + x*srcW/width
			r, g, b, a := src.At(sx, sy).RGBA()
			dst.SetRGBA(x, y, color.RGBA{
				R: uint8(r >> 8),
				G: uint8(g >> 8),
				B: uint8(b >> 8),
				A: uint8(a >> 8),
			})
		}
	}
	return dst
}

func tokenFromPath(prefix, fullPath string) string {
	token := strings.TrimPrefix(fullPath, prefix)
	if dot := strings.LastIndex(token, "."); dot >= 0 {
		token = token[:dot]
	}
	if token == "" || strings.Contains(token, "/") {
		return ""
	}
	return token
}

func sanitizeTrace(points []tracePoint, sliderMax float64) []tracePoint {
	if len(points) == 0 {
		return nil
	}

	clean := make([]tracePoint, 0, len(points))
	var lastT int64 = -1
	for _, point := range points {
		if math.IsNaN(point.X) || math.IsNaN(point.Y) || math.IsInf(point.X, 0) || math.IsInf(point.Y, 0) {
			continue
		}
		if point.T < 0 || point.T <= lastT {
			continue
		}
		if point.X < -5 || point.X > sliderMax+5 {
			continue
		}
		if math.Abs(point.Y) > 160 {
			continue
		}

		clean = append(clean, point)
		lastT = point.T
	}
	return clean
}

func randomToken(size int) (string, error) {
	buf, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func randomInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func randomIntRange(minValue, maxValue int) (int, error) {
	if maxValue < minValue {
		return 0, fmt.Errorf("invalid range")
	}
	delta, err := randomInt(maxValue - minValue + 1)
	if err != nil {
		return 0, err
	}
	return minValue + delta, nil
}

func stddev(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := 0.0
	for _, value := range values {
		mean += value
	}
	mean /= float64(len(values))

	variance := 0.0
	for _, value := range values {
		diff := value - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	return math.Sqrt(variance)
}

func round(value float64, places int) float64 {
	pow := math.Pow10(places)
	return math.Round(value*pow) / pow
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	writeNoCache(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeNoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}
