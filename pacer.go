package main

import (
	"io"
	"time"
)

// ─── Bandwidth pacer ────────────────────────────────────────────────────────

// pacer keeps a stream under a bitrate.
//
// BandwidthMbps has been stored per user since the tier system landed and
// advertised in the README as "1 / 5 / 50 Mbps", but nothing ever read it:
// relay() was a plain io.Copy in both directions, so the Free tier ran at line
// speed like every other tier. This is where that column finally takes effect.
//
// A token bucket with a one-second burst, which is what a tier limit means in
// practice: sustained rate capped, short spikes allowed. Each direction gets its
// own pacer, so a tier's number is the rate in each direction rather than a
// shared budget -- the usual reading of a per-tier bandwidth figure, and the one
// that keeps a download from starving the upload that ACKs it.
type pacer struct {
	bytesPerSec float64
	tokens      float64
	last        time.Time
}

// pacerBurstSeconds is how much slack a client gets before the average rate
// kicks in. One second of traffic is enough to smooth a burst without letting a
// fast transfer spend its whole allowance at once.
const pacerBurstSeconds = 1.0

// newPacer returns nil when there is nothing to enforce, which is the -1 that
// the Unlimited tier uses. Callers treat a nil pacer as "copy at full speed", so
// the unlimited path keeps costing nothing.
func newPacer(mbps int) *pacer {
	if mbps <= 0 {
		return nil
	}
	rate := float64(mbps) * 1024 * 1024 / 8 // Mbit/s -> bytes/s
	return &pacer{
		bytesPerSec: rate,
		tokens:      rate * pacerBurstSeconds,
		last:        time.Now(),
	}
}

// reserve asks for permission to move n bytes, sleeping if the allowance for
// this instant is not there yet.
func (p *pacer) reserve(n int) {
	if p == nil || n <= 0 {
		return
	}
	now := time.Now()
	p.tokens += now.Sub(p.last).Seconds() * p.bytesPerSec
	p.last = now
	if p.tokens > p.bytesPerSec*pacerBurstSeconds {
		p.tokens = p.bytesPerSec * pacerBurstSeconds
	}
	p.tokens -= float64(n)
	if p.tokens >= 0 {
		return
	}
	// Negative tokens are the debt: wait for the bucket to refill by that much.
	debt := -p.tokens
	p.tokens = 0
	time.Sleep(time.Duration(debt / p.bytesPerSec * float64(time.Second)))
	// The clock has to be moved past the sleep. Without this the next call
	// credits the sleeping interval as if it were idle time, so the debt is
	// paid twice and the link runs at twice the configured rate.
	p.last = time.Now()
}

// copyPaced is io.Copy with a rate limit. The read/write loop replaces io.Copy
// because pacing needs to sit between the two, and because the chunk size is
// what the pacer reserves against.
func copyPaced(dst io.Writer, src io.Reader, p *pacer) (int64, error) {
	if p == nil {
		return io.Copy(dst, src)
	}
	buf := make([]byte, pacerChunkSize)
	var total int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				total += int64(nw)
				p.reserve(nw)
			}
			if werr != nil {
				return total, werr
			}
			if nw != nr {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

// pacerChunkSize is the read size for paced copies. 32KB keeps the sleep count
// low on a fast link while staying small enough that a rate limit of 1 Mbps
// still arrives in ~4 chunks a second instead of a single one-second stall.
const pacerChunkSize = 32 << 10
