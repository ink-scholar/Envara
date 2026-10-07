package fingerprint

import "fmt"

// GeoIP-based fingerprint adjustment

var countryToGeo = map[string]geoInfo{
	"US": {Timezone: "America/New_York", Language: "en-US", Languages: []string{"en-US", "en"}},
	"GB": {Timezone: "Europe/London", Language: "en-GB", Languages: []string{"en-GB", "en"}},
	"DE": {Timezone: "Europe/Berlin", Language: "de-DE", Languages: []string{"de-DE", "de", "en"}},
	"FR": {Timezone: "Europe/Paris", Language: "fr-FR", Languages: []string{"fr-FR", "fr", "en"}},
	"JP": {Timezone: "Asia/Tokyo", Language: "ja-JP", Languages: []string{"ja-JP", "ja", "en"}},
	"KR": {Timezone: "Asia/Seoul", Language: "ko-KR", Languages: []string{"ko-KR", "ko", "en"}},
	"TW": {Timezone: "Asia/Taipei", Language: "zh-TW", Languages: []string{"zh-TW", "zh", "en"}},
	"CN": {Timezone: "Asia/Shanghai", Language: "zh-CN", Languages: []string{"zh-CN", "zh", "en"}},
	"HK": {Timezone: "Asia/Hong_Kong", Language: "zh-HK", Languages: []string{"zh-HK", "zh", "en"}},
	"SG": {Timezone: "Asia/Singapore", Language: "en-SG", Languages: []string{"en-SG", "en", "zh"}},
	"AU": {Timezone: "Australia/Sydney", Language: "en-AU", Languages: []string{"en-AU", "en"}},
	"CA": {Timezone: "America/Toronto", Language: "en-CA", Languages: []string{"en-CA", "en", "fr"}},
	"BR": {Timezone: "America/Sao_Paulo", Language: "pt-BR", Languages: []string{"pt-BR", "pt", "en"}},
	"RU": {Timezone: "Europe/Moscow", Language: "ru-RU", Languages: []string{"ru-RU", "ru", "en"}},
	"IN": {Timezone: "Asia/Kolkata", Language: "en-IN", Languages: []string{"en-IN", "hi", "en"}},
	"TH": {Timezone: "Asia/Bangkok", Language: "th-TH", Languages: []string{"th-TH", "th", "en"}},
	"VN": {Timezone: "Asia/Ho_Chi_Minh", Language: "vi-VN", Languages: []string{"vi-VN", "vi", "en"}},
	"ID": {Timezone: "Asia/Jakarta", Language: "id-ID", Languages: []string{"id-ID", "id", "en"}},
	"PH": {Timezone: "Asia/Manila", Language: "en-PH", Languages: []string{"en-PH", "fil", "en"}},
	"MY": {Timezone: "Asia/Kuala_Lumpur", Language: "ms-MY", Languages: []string{"ms-MY", "ms", "en"}},
	"NL": {Timezone: "Europe/Amsterdam", Language: "nl-NL", Languages: []string{"nl-NL", "nl", "en"}},
	"IT": {Timezone: "Europe/Rome", Language: "it-IT", Languages: []string{"it-IT", "it", "en"}},
	"ES": {Timezone: "Europe/Madrid", Language: "es-ES", Languages: []string{"es-ES", "es", "en"}},
	"MX": {Timezone: "America/Mexico_City", Language: "es-MX", Languages: []string{"es-MX", "es", "en"}},
	"SE": {Timezone: "Europe/Stockholm", Language: "sv-SE", Languages: []string{"sv-SE", "sv", "en"}},
	"PL": {Timezone: "Europe/Warsaw", Language: "pl-PL", Languages: []string{"pl-PL", "pl", "en"}},
	"TR": {Timezone: "Europe/Istanbul", Language: "tr-TR", Languages: []string{"tr-TR", "tr", "en"}},
	"UA": {Timezone: "Europe/Kyiv", Language: "uk-UA", Languages: []string{"uk-UA", "uk", "en"}},
	"IL": {Timezone: "Asia/Jerusalem", Language: "he-IL", Languages: []string{"he-IL", "he", "en"}},
	"AE": {Timezone: "Asia/Dubai", Language: "ar-AE", Languages: []string{"ar-AE", "ar", "en"}},
}

type geoInfo struct {
	Timezone  string
	Language  string
	Languages []string
}

// AdjustForCountry overwrites geo-dependent fingerprint fields based on country code
func AdjustForCountry(fp map[string]any, countryCode string) {
	geo, ok := countryToGeo[countryCode]
	if !ok {
		geo = countryToGeo["US"] // fallback
	}

	fp["timezone"] = geo.Timezone
	fp["locale:language"] = geo.Language[:2]
	fp["locale:region"] = countryCode
	fp["navigator.language"] = geo.Language
	fp["navigator.languages"] = geo.Languages
	fp["headers.Accept-Language"] = buildAcceptLanguage(geo.Languages)
}

func buildAcceptLanguage(langs []string) string {
	if len(langs) == 0 {
		return "en-US,en;q=0.9"
	}
	result := langs[0]
	for i := 1; i < len(langs); i++ {
		q := 1.0 - float64(i)*0.1
		if q < 0.1 {
			q = 0.1
		}
		result += fmt.Sprintf(",%s;q=%.1f", langs[i], q)
	}
	return result
}
