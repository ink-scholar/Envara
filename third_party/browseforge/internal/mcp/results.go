package mcp

import "encoding/base64"

func textResult(text string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

func imageResult(data []byte) map[string]any {
	return imageResultWithMime(data, "image/jpeg")
}

func imageResultWithMime(data []byte, mimeType string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "image", "data": base64.StdEncoding.EncodeToString(data), "mimeType": mimeType}}}
}
