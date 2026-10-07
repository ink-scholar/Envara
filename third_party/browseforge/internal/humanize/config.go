package humanize

// Config controls human-like behavior simulation.
type Config struct {
	Enabled     bool    `json:"enabled"`
	MouseSpeed  string  `json:"mouse_speed"`  // "fast", "normal", "slow"
	TypingCPM   int     `json:"typing_cpm"`   // characters per minute
	TypoRate    float64 `json:"typo_rate"`     // 0.0–1.0
	ScrollStyle string  `json:"scroll_style"` // "smooth", "instant"
}

// DefaultConfig returns the default humanize configuration (enabled).
func DefaultConfig() Config {
	return Config{
		Enabled:     true,
		MouseSpeed:  "normal",
		TypingCPM:   500,
		TypoRate:    0.02,
		ScrollStyle: "smooth",
	}
}

// ConfigFromRaw builds a Config from raw config values (from config.HumanizeConfig).
// Missing/zero values fall back to defaults.
func ConfigFromRaw(enabled *bool, mouseSpeed string, typingCPM int, typoRate *float64, scrollStyle string) Config {
	c := DefaultConfig()
	if enabled != nil {
		c.Enabled = *enabled
	}
	if mouseSpeed != "" {
		c.MouseSpeed = mouseSpeed
	}
	if typingCPM > 0 {
		c.TypingCPM = typingCPM
	}
	if typoRate != nil {
		c.TypoRate = *typoRate
	}
	if scrollStyle != "" {
		c.ScrollStyle = scrollStyle
	}
	return c
}

// mouseParams returns step/timing parameters based on speed preset.
func (c Config) mouseParams() (minSteps, maxSteps int, microPauseMs [2]int) {
	switch c.MouseSpeed {
	case "fast":
		return 35, 60, [2]int{20, 50}
	case "slow":
		return 60, 120, [2]int{40, 90}
	default: // "normal"
		return 45, 90, [2]int{30, 70}
	}
}
