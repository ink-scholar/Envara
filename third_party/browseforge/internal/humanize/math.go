package humanize

import (
	"math"
	"math/rand/v2"
)

// vec2 is a 2D point/vector.
type vec2 struct{ X, Y float64 }

func (a vec2) add(b vec2) vec2    { return vec2{a.X + b.X, a.Y + b.Y} }
func (a vec2) sub(b vec2) vec2    { return vec2{a.X - b.X, a.Y - b.Y} }
func (a vec2) scale(s float64) vec2 { return vec2{a.X * s, a.Y * s} }
func (a vec2) length() float64    { return math.Sqrt(a.X*a.X + a.Y*a.Y) }
func (a vec2) perp() vec2         { return vec2{a.Y, -a.X} }

func (a vec2) normalize() vec2 {
	l := a.length()
	if l == 0 {
		return vec2{}
	}
	return vec2{a.X / l, a.Y / l}
}

// bezierPoint evaluates cubic Bézier at parameter t.
func bezierPoint(p0, p1, p2, p3 vec2, t float64) vec2 {
	u := 1 - t
	return p0.scale(u * u * u).add(
		p1.scale(3 * u * u * t)).add(
		p2.scale(3 * u * t * t)).add(
		p3.scale(t * t * t))
}

// bezierPath generates a human-like Bézier path from start to end.
// Uses ghost-cursor's same-side anchor algorithm + Gaussian easing.
func bezierPath(start, end vec2, steps int) []vec2 {
	dir := end.sub(start)
	dist := dir.length()
	if dist < 1 {
		return []vec2{end}
	}

	// Spread: how far anchors deviate from the straight line
	// Minimum 15px ensures visible curvature even for short moves
	spread := math.Min(math.Max(dist*0.4, 15), 200)

	// Both anchors on the same side (ghost-cursor insight: avoids S-curves)
	side := 1.0
	if rand.Float64() < 0.5 {
		side = -1
	}

	anchor := func() vec2 {
		// Random point along the line segment
		t := rand.Float64()
		mid := start.add(dir.scale(t))
		// Perpendicular offset
		perpDir := dir.normalize().perp().scale(spread * side)
		return mid.add(perpDir.scale(rand.Float64()))
	}

	p1, p2 := anchor(), anchor()
	// Sort by progress along the direction (dot product with dir)
	if dir.X*(p2.X-start.X)+dir.Y*(p2.Y-start.Y) < dir.X*(p1.X-start.X)+dir.Y*(p1.Y-start.Y) {
		p1, p2 = p2, p1
	}

	// Generate points with Gaussian easing (slow-fast-slow)
	pts := make([]vec2, steps)
	for i := range steps {
		// Map uniform [0,1] through Gaussian CDF for easing
		u := float64(i) / float64(steps-1)
		t := gaussianEase(u)
		pt := bezierPoint(start, p1, p2, end, t)
		// Add micro-jitter (Gaussian, σ=1px)
		pt.X += rand.NormFloat64()
		pt.Y += rand.NormFloat64()
		pts[i] = pt
	}
	return pts
}

// gaussianEase remaps [0,1] through a sigmoid curve, normalized to [0,1].
// Produces slow start, fast middle, slow end — matching human velocity profiles.
func gaussianEase(t float64) float64 {
	x := (t - 0.5) * 5
	raw := 1.0 / (1.0 + math.Exp(-x))
	// Normalize: sigmoid(−2.5)→0, sigmoid(2.5)→1
	lo := 1.0 / (1.0 + math.Exp(2.5))
	hi := 1.0 / (1.0 + math.Exp(-2.5))
	return (raw - lo) / (hi - lo)
}

// overshootPoint generates a random point within a circle around target.
// Uses sqrt(random) for uniform area distribution.
func overshootPoint(target vec2, radius float64) vec2 {
	angle := rand.Float64() * 2 * math.Pi
	r := radius * math.Sqrt(rand.Float64())
	return target.add(vec2{r * math.Cos(angle), r * math.Sin(angle)})
}

// fittsSteps calculates step count using Fitts's Law (Shannon formulation).
func fittsSteps(dist, targetWidth float64, minSteps, maxSteps int) int {
	if targetWidth <= 0 {
		targetWidth = 100
	}
	id := math.Log2(dist/targetWidth + 1)
	base := rand.Float64() * float64(minSteps)
	steps := int(math.Ceil((math.Log2(2*id+1) + base) * 3))
	return max(minSteps, min(steps, maxSteps))
}

// logNormalDelay returns a random delay (ms) from a log-normal distribution.
func logNormalDelay(mu, sigma float64) float64 {
	return math.Exp(mu + sigma*rand.NormFloat64())
}

// randRange returns a random float64 in [lo, hi].
func randRange(lo, hi float64) float64 {
	return lo + rand.Float64()*(hi-lo)
}

// randRangeInt returns a random int in [lo, hi].
func randRangeInt(lo, hi int) int {
	if lo >= hi {
		return lo
	}
	return lo + rand.IntN(hi-lo+1)
}
