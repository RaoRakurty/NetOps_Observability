package collectors

import (
	"math"
	"testing"
)

func almost(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestLossPct(t *testing.T) {
	cases := []struct {
		sent, recv int
		want       float64
	}{
		{10, 10, 0},
		{10, 9, 10},
		{10, 0, 100},
		{0, 0, 0}, // no probes sent → not "100% loss"
		{5, 7, 0}, // recv clamped to sent, never negative loss
	}
	for _, c := range cases {
		if got := lossPct(c.sent, c.recv); !almost(got, c.want) {
			t.Errorf("lossPct(%d,%d)=%.2f want %.2f", c.sent, c.recv, got, c.want)
		}
	}
}

func TestMeanRTT(t *testing.T) {
	if got := meanRTT(nil); got != 0 {
		t.Errorf("meanRTT(nil)=%v want 0", got)
	}
	if got := meanRTT([]float64{10, 20, 30}); !almost(got, 20) {
		t.Errorf("meanRTT=%v want 20", got)
	}
}

// jitter = mean |consecutive delta| (RFC 3550 form).
func TestJitterMs(t *testing.T) {
	if got := jitterMs([]float64{10}); got != 0 {
		t.Errorf("single sample jitter=%v want 0", got)
	}
	// deltas: |12-10|, |11-12|, |15-11| = 2,1,4 → mean 7/3.
	if got := jitterMs([]float64{10, 12, 11, 15}); !almost(got, 7.0/3.0) {
		t.Errorf("jitter=%v want %v", got, 7.0/3.0)
	}
	// constant RTT → zero jitter.
	if got := jitterMs([]float64{20, 20, 20, 20}); got != 0 {
		t.Errorf("constant-rtt jitter=%v want 0", got)
	}
}

func TestQoEScore(t *testing.T) {
	// Pristine path → 10.
	if got := qoeScore(5, 1, 0); !almost(got, 10) {
		t.Errorf("pristine qoe=%v want 10", got)
	}
	// Catastrophic on every axis → 0.
	if got := qoeScore(400, 100, 20); !almost(got, 0) {
		t.Errorf("dead-path qoe=%v want 0", got)
	}
	// A single bad dimension (loss) drags the score well below average — the
	// worst-dimension behaviour, not a simple mean.
	good := qoeScore(20, 5, 0)   // all good
	oneBad := qoeScore(20, 5, 8) // loss maxed, latency+jitter still good
	if !(oneBad < good && oneBad < 5) {
		t.Errorf("one-bad-dimension qoe=%v should be pulled well down (good=%v)", oneBad, good)
	}
	// Monotonic: worse loss never scores higher.
	if qoeScore(50, 10, 3) > qoeScore(50, 10, 1) {
		t.Error("higher loss must not score higher")
	}
}

func TestScoreLinear(t *testing.T) {
	if got := scoreLinear(40, 50, 300); got != 10 {
		t.Errorf("below-good=%v want 10", got)
	}
	if got := scoreLinear(300, 50, 300); got != 0 {
		t.Errorf("at-bad=%v want 0", got)
	}
	if got := scoreLinear(175, 50, 300); !almost(got, 5) {
		t.Errorf("midpoint=%v want 5", got)
	}
}

func TestEchoTargetsEnvFallback(t *testing.T) {
	t.Setenv("REDIS_HOST", "") // force the env path (no Redis)
	t.Setenv("WAN_ECHO_TARGETS", "10.0.0.1, 192.0.2.10=198.51.100.5 , ")
	got := echoTargets(nil)
	if len(got) != 2 {
		t.Fatalf("parsed %d targets, want 2: %+v", len(got), got)
	}
	if got[0].RemoteAddr != "10.0.0.1" || got[0].LocalAddr != "" {
		t.Errorf("target[0]=%+v want remote=10.0.0.1 local empty", got[0])
	}
	if got[1].LocalAddr != "192.0.2.10" || got[1].RemoteAddr != "198.51.100.5" {
		t.Errorf("target[1]=%+v want local=192.0.2.10 remote=198.51.100.5", got[1])
	}
}

func TestSummarizeNoLossEndToEnd(t *testing.T) {
	res := echoResult{sent: 4, recv: 4, method: "icmp"}
	summarize(&res, []float64{10, 12, 11, 15})
	if !almost(res.lossPct, 0) {
		t.Errorf("loss=%v want 0", res.lossPct)
	}
	if !almost(res.latencyMs, 12) { // mean of 10,12,11,15 = 12
		t.Errorf("latency=%v want 12", res.latencyMs)
	}
	if res.jitterMs <= 0 {
		t.Errorf("jitter should be > 0 for a varying series, got %v", res.jitterMs)
	}
	if res.qoe <= 0 || res.qoe > 10 {
		t.Errorf("qoe out of range: %v", res.qoe)
	}
}
