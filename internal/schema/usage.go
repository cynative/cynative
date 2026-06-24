package schema

// Usage is the token accounting reported by the model backend for one or more
// chat-completion calls. The zero value means "no usage reported".
type Usage struct {
	PromptTokens      int
	CompletionTokens  int
	TotalTokens       int
	CachedReadTokens  int
	CachedWriteTokens int
}
