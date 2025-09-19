package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const ADDR = "0.0.0.0"
const PORT = 15000
const JWT_SECRET = "some-super-duper-secret"

var uidCounter uint64 = 0

var users []User
var clients []Client
var sessions []*Session

var authCodeStorage *InMemoryCodeStorage

type User struct {
	userId   string
	email    string
	password string
}

type Client struct {
	clientId    string
	redirectUri []string
}

type Session struct {
	sessionId     string
	responseType  string
	clientId      string
	redirectUri   string
	authenticated bool
	userId        string
}

type ErrorResp struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type RedirectResp struct {
	RedirectUri string `json:"redirect_uri"`
}

type AuthCodeData struct {
	code      string
	sessionId string
	createdAt time.Time
	expiresAt time.Time
}

type CodeStorage interface {
	Save(code string, codeData *AuthCodeData, ttl time.Duration) error
	Consume(code string) (codeData *AuthCodeData, err error)
}

var (
	ErrCodeNotFound  = errors.New("auth code not found")
	ErrorCodeExpired = errors.New("auth code expired")
)

type InMemoryCodeStorage struct {
	mu    sync.Mutex
	data  map[string]*AuthCodeData
	ticks time.Duration
	quit  chan struct{}
}

func (s *InMemoryCodeStorage) cleanupLoop() {
	ticker := time.NewTicker(s.ticks)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, v := range s.data {
				if now.After(v.expiresAt) {
					delete(s.data, k)
				}
			}
			s.mu.Unlock()
		case <-s.quit:
			return
		}
	}
}

func (s *InMemoryCodeStorage) Close() {
	close(s.quit)
}

func NewInMemoryCodeStorage(cleanupInterval time.Duration) *InMemoryCodeStorage {
	storage := &InMemoryCodeStorage{
		data:  make(map[string]*AuthCodeData),
		ticks: cleanupInterval,
		quit:  make(chan struct{}),
	}
	if cleanupInterval > 0 {
		go storage.cleanupLoop()
	}
	return storage
}

func (s *InMemoryCodeStorage) Save(code string, codeData *AuthCodeData, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[code]; exists {
		return fmt.Errorf("code %s already exists", code)
	}
	codeData.expiresAt = time.Now().Add(ttl)
	s.data[code] = codeData
	return nil
}

func (s *InMemoryCodeStorage) Consume(code string) (codeData *AuthCodeData, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.data[code]
	if !ok {
		return nil, ErrCodeNotFound
	}
	if time.Now().After(ac.expiresAt) {
		delete(s.data, code)
		return nil, ErrorCodeExpired
	}
	delete(s.data, code)
	return ac, nil
}

func IssueAuthCode(store *InMemoryCodeStorage, sessionId string, ttl time.Duration) (string, error) {
	const maxRetry = 10
	for i := 0; i < maxRetry; i++ {
		code, err := randomIdGenerator()
		if err != nil {
			return "", err
		}
		authCodeData := &AuthCodeData{
			code:      code,
			sessionId: sessionId,
			createdAt: time.Now(),
		}
		if err := store.Save(code, authCodeData, ttl); err == nil {
			return code, nil
		}
	}
	return "", errors.New("failed to generate auth code")
}

func randomIdGenerator() (string, error) {
	ts := strconv.FormatInt(time.Now().UTC().UnixNano(), 36)

	const randBytesLen = 24
	rb := make([]byte, randBytesLen)
	if _, err := rand.Read(rb); err != nil {
		return "", err
	}
	randHex := hex.EncodeToString(rb)

	buf := fmt.Sprintf("%s-%s", ts, randHex)
	id := base64.RawURLEncoding.EncodeToString([]byte(buf))
	return id, nil
}

func writeJSONError(w http.ResponseWriter, status int, errMsg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(ErrorResp{Error: http.StatusText(status), Message: errMsg})
	if err != nil {
		return
	}
}

func clientPrefersJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" || accept == "*/*" || strings.Contains(accept, "application/json") || strings.Contains(accept, "+json") {
		return true
	}
	if strings.Contains(accept, "text/plain") {
		return false
	}
	return true
}

var allowedOrigins = []string{
	"http://localhost:3000",
}

func registerParentService() error {
	clients = append(clients, Client{
		clientId:    "parent",
		redirectUri: []string{"http://localhost:3000/api/auth/callback"},
	})
	return nil
}

func isAllowedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	for _, o := range allowedOrigins {
		if o == origin {
			return true
		}
	}
	return false
}

func loggingMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		handler.ServeHTTP(w, r)
		fmt.Printf("%v %v [%v] \"%v\" from %v (%v ms)\n",
			start.Format(time.DateTime),
			r.Proto,
			r.Method,
			r.URL,
			r.RemoteAddr,
			time.Since(start).Milliseconds())
	})
}

func corsMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")
			w.Header().Set("Access-Control-Expose-Headers", "Location, Content-Disposition")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("OK"))
	if err != nil {
		return
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	queryResponseType := query.Get("response_type")
	queryClientId := query.Get("client_id")
	queryRedirectUri := query.Get("redirect_uri")
	if queryResponseType == "" || queryClientId == "" || queryRedirectUri == "" {
		fmt.Println("Missing required query parameters.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionId := ""
	sessionIdCookie, err := r.Cookie("session_id")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			sessionId = ""
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Printf("Error getting session_id from cookie: %v\n", err)
			return
		}
	}
	if sessionIdCookie != nil {
		sessionId = sessionIdCookie.Value
	}

	sessionIdx := -1
	if sessionId != "" {
		for i, session := range sessions {
			if (*session).sessionId == sessionId {
				sessionIdx = i
				break
			}
		}
	}

	if sessionIdx >= 0 {
		fmt.Printf("Found session with id %s\n", sessionId)
		session := sessions[sessionIdx]
		// validate session
		if queryResponseType != session.responseType {
			fmt.Printf("Invalid response type %s\n", queryResponseType)
			goto newSession
		}
		if queryClientId != session.clientId {
			fmt.Printf("Invalid client id %s\n", queryClientId)
			goto newSession
		}
		found := false
		var clientPtr *Client
		for _, client := range clients {
			if client.clientId == queryClientId {
				found = true
				clientPtr = &client
			}
		}
		if !found {
			fmt.Printf("Client id %s not found\n", queryClientId)
			goto newSession
		}
		if queryResponseType != session.responseType {
			fmt.Printf("Invalid response type %s\n", queryResponseType)
			goto newSession
		}
		if clientPtr == nil {
			fmt.Printf("Invalid client pointer\n")
			goto newSession
		}
		found = false
		for _, redirectUri := range (*clientPtr).redirectUri {
			if redirectUri == queryRedirectUri {
				found = true
			}
		}
		if !found {
			fmt.Printf("Invalid redirect URI %s\n", queryRedirectUri)
			goto newSession
		}
		if !(*session).authenticated {
			fmt.Printf("Session not authenticated\n")
			goto newSession
		}
		if (*session).userId == "" {
			fmt.Printf("Invalid user id\n")
			goto newSession
		}
		found = false
		for _, u := range users {
			if u.userId == (*session).userId {
				found = true
			}
		}
		if !found {
			fmt.Printf("user not found\n")
			goto newSession
		}
		newCode, err := IssueAuthCode(authCodeStorage, sessionId, 2*time.Minute)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Printf("Error issuing auth code: %v\n", err)
			return
		}
		fullRedirectUri := fmt.Sprintf("%v?code=%v", queryRedirectUri, newCode)
		http.Redirect(w, r, fullRedirectUri, http.StatusFound)
		return
	}
newSession:
	newSessionId, err := randomIdGenerator()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Printf("Error generating session_id: %v\n", err)
		return
	}
	fmt.Println("New session created:", newSessionId)
	var session Session
	session.sessionId = newSessionId
	session.responseType = queryResponseType
	session.clientId = queryClientId
	session.redirectUri = queryRedirectUri
	session.authenticated = false
	sessions = append(sessions, &session)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:  "session_id",
		Path:  "/",
		Value: newSessionId,
	})
	http.Redirect(w, r, "http://localhost:3000/login", http.StatusFound)
	return
}

func validateBasicAuth(authHeader string, allowedClient string) bool {
	if authHeader == "" {
		return false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}
	b64 := strings.TrimPrefix(authHeader, prefix)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return false
	}
	return string(decoded) == allowedClient
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Token exchange request")
	if r.Method != "POST" {
		fmt.Println("Method not allowed:", r.Method)
		writeJSONError(w, http.StatusBadRequest, "Method not allowed")
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		fmt.Println("Content-Type not application/json")
		writeJSONError(w, http.StatusBadRequest, "content-type is not application/json")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		writeJSONError(w, http.StatusBadRequest, "Error reading body")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		fmt.Println("Error parsing body:", err)
		writeJSONError(w, http.StatusBadRequest, "Error parsing body")
	}
	if strings.TrimSpace(req.Code) == "" {
		fmt.Println("Invalid code")
		writeJSONError(w, http.StatusBadRequest, "Code is required")
		return
	}
	codeData, err := authCodeStorage.Consume(req.Code)
	if err != nil {
		fmt.Println("Error consuming code:", err)
		writeJSONError(w, http.StatusBadRequest, "Error consuming code")
		return
	}
	var session *Session
	for _, s := range sessions {
		if s.sessionId == codeData.sessionId {
			session = s
			break
		}
	}
	if session == nil {
		fmt.Println("Session not found")
		writeJSONError(w, http.StatusBadRequest, "Session not found")
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !validateBasicAuth(authHeader, session.clientId) {
		fmt.Println("Invalid auth header:", authHeader)
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		writeJSONError(w, http.StatusUnauthorized, "Invalid authorization header")
	}

	jwtKey := JWT_SECRET

	now := time.Now()
	expireIn := time.Second * 30
	claims := jwt.MapClaims{
		"iss":  "http://localhost:15000",
		"sub":  session.userId,
		"iat":  now.Unix(),
		"exp":  now.Add(expireIn).Unix(),
		"code": req.Code,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtKey))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Error signing token")
		return
	}
	fmt.Println("Token generated:", tokenString)

	resp := map[string]interface{}{
		"access_token": tokenString,
		"token_type":   "Bearer",
		"expires_in":   int64(expireIn.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		return
	}
	return
}

func whoamiIntrospectionHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Token Who am I introspection request")
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		fmt.Println("Invalid authorization header:", auth)
		writeJSONError(w, http.StatusUnauthorized, "Invalid authorization header")
		return
	}

	tokenString := strings.TrimPrefix(auth, "Bearer ")
	jwtKey := JWT_SECRET

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtKey), nil
	}

	token, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		fmt.Println("Error parsing token:", err)
		writeJSONError(w, http.StatusUnauthorized, "Invalid or expired authorization header")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	var user *User
	fmt.Println("userID", claims["sub"])
	for _, u := range users {
		fmt.Println("user iter:", u.userId)
		if u.userId == claims["sub"] {
			user = &u
			break
		}
	}
	email := ""
	if user == nil {
		fmt.Println("User not found")
		ok = false
	} else {
		email = user.email
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"authorized": ok,
		"sub":        claims["sub"],
		"email":      email,
	})
}

func userLoginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("User login request")
	if r.Method != "POST" {
		fmt.Printf("Method not allowed: %v\n", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	sessionId := ""
	sessionIdCookie, err := r.Cookie("session_id")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			sessionId = ""
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Printf("Error getting session_id from cookie: %v\n", err)
			return
		}
	}
	if sessionIdCookie != nil {
		sessionId = sessionIdCookie.Value
	}
	var session *Session = nil
	for _, s := range sessions {
		if (*s).sessionId == sessionId {
			session = s
			break
		}
	}
	if session == nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Printf("Session ID not found: %v\n", sessionId)
		return
	}

	var email string
	var password string
	contentType := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(contentType, "application/json"):
		// TODO
	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		if err := r.ParseForm(); err != nil {
			msg := fmt.Sprintf("Error parsing form: %v\n", err)
			fmt.Println(msg)
			if clientPrefersJSON(r) {
				writeJSONError(w, http.StatusBadRequest, msg)
			} else {
				http.Error(w, msg, http.StatusBadRequest)
			}
			return
		}
		if !r.Form.Has("email") || !r.Form.Has("password") {
			msg := fmt.Sprintf("Missing required field \"email\" or \"password\"")
			fmt.Println(msg)
			if clientPrefersJSON(r) {
				writeJSONError(w, http.StatusBadRequest, msg)
			} else {
				http.Error(w, msg, http.StatusBadRequest)
			}
			return
		}
		email = r.Form.Get("email")
		password = r.Form.Get("password")
	case strings.HasPrefix(contentType, "multipart/form-data"):
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			msg := fmt.Sprintf("Error parsing multipart form: %v\n", err)
			fmt.Println(msg)
			if clientPrefersJSON(r) {
				writeJSONError(w, http.StatusBadRequest, msg)
			} else {
				http.Error(w, msg, http.StatusBadRequest)
			}
			return
		}
		email = r.PostFormValue("email")
		password = r.PostFormValue("password")
	}
	fmt.Printf("email: %v\n", email)
	fmt.Printf("password: %v\n", password)
	userId := ""
	for _, user := range users {
		if user.email == email && user.password == password {
			userId = user.userId
		}
	}
	if userId == "" {
		msg := fmt.Sprintf("Invalid email or password")
		fmt.Println(msg)
		if clientPrefersJSON(r) {
			writeJSONError(w, http.StatusUnauthorized, msg)
		} else {
			http.Error(w, msg, http.StatusUnauthorized)
		}
		return
	}
	(*session).userId = userId
	(*session).authenticated = true
	newCode, err := IssueAuthCode(authCodeStorage, sessionId, 2*time.Minute)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Printf("Error issuing auth code: %v\n", err)
		return
	}
	fullRedirectUri := fmt.Sprintf("%v?code=%v", (*session).redirectUri, newCode)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(RedirectResp{RedirectUri: fullRedirectUri})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Println("Login success: redirecting to", fullRedirectUri)
}

func userRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("User registration request\n")
	if r.Method != "POST" {
		fmt.Printf("Method not allowed\n")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var user = User{}
	contentType := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(contentType, "application/json"):
		// TODO
	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		if err := r.ParseForm(); err != nil {
			msg := fmt.Sprintf("Error parsing form: %v\n", err)
			fmt.Printf(msg)
			if clientPrefersJSON(r) {
				writeJSONError(w, http.StatusBadRequest, msg)
			} else {
				http.Error(w, msg, http.StatusBadRequest)
			}
			return
		}
		if !r.Form.Has("email") || !r.Form.Has("password") {
			msg := fmt.Sprintf("Email or password is missing\n")
			fmt.Printf(msg)
			if clientPrefersJSON(r) {
				writeJSONError(w, http.StatusBadRequest, msg)
			} else {
				http.Error(w, msg, http.StatusBadRequest)
			}
			return
		}
		user.userId = strconv.FormatUint(uidCounter, 10)
		user.email = r.PostFormValue("email")
		user.password = r.PostFormValue("password")
	case strings.HasPrefix(contentType, "multipart/form-data"):
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			msg := fmt.Sprintf("Error parsing multipart form: %v\n", err)
			fmt.Printf(msg)
			if clientPrefersJSON(r) {
				writeJSONError(w, http.StatusBadRequest, msg)
			} else {
				http.Error(w, msg, http.StatusBadRequest)
			}
			return
		}
		user.userId = strconv.FormatUint(uidCounter, 10)
		user.email = r.PostFormValue("email")
		user.password = r.PostFormValue("password")
	}

	for i := range users {
		if users[i].email == user.email {
			msg := fmt.Sprintf("User already registered\n")
			fmt.Printf(msg)
			if clientPrefersJSON(r) {
				writeJSONError(w, http.StatusBadRequest, msg)
			} else {
				http.Error(w, msg, http.StatusBadRequest)
			}
			return
		}
	}
	uidCounter++
	users = append(users, user)
	fmt.Printf("User registered: %v\n", user)
	w.WriteHeader(http.StatusCreated)
}

func main() {
	fmt.Printf("Akashic running on %v:%v\n", ADDR, PORT)
	authCodeStorage = NewInMemoryCodeStorage(1 * time.Minute)
	defer authCodeStorage.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/auth/authorize", authHandler)
	mux.HandleFunc("/auth/token", tokenHandler)
	mux.HandleFunc("/auth/whoami", whoamiIntrospectionHandler)
	mux.HandleFunc("/api/user/register", userRegistrationHandler)
	mux.HandleFunc("/api/user/login", userLoginHandler)
	err := registerParentService()
	if err != nil {
		return
	}
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%v:%v", ADDR, PORT), loggingMiddleware(corsMiddleware(mux))))
}
