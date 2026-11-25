package analyzer

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"sort"
)

// addrRange is an inclusive range of addresses of one family.
type addrRange struct {
	lo, hi netip.Addr
}

// addrSet is a set of source addresses, kept as sorted, disjoint ranges that
// do not touch. A rule that excludes one address from 0.0.0.0/0 leaves two
// ranges; as a list of prefixes it would leave 32, and a blocklist of a few
// thousand addresses made every later rule scan hundreds of thousands of
// prefixes.
//
// The ranges are stored in chunks, so that taking one address out of a set
// with tens of thousands of ranges copies one chunk and not the whole set.
// Sets are immutable: every operation returns a set that may share chunks
// with its operands. The zero value is the empty set.
type addrSet struct {
	chunks [][]addrRange // each non-empty; all ranges in ascending order
}

// A chunk is created with at most chunkSize ranges.
const chunkSize = 256

// makeSet returns the set of ranges that are sorted, disjoint and do not
// touch. The chunks share the backing array of ranges.
func makeSet(ranges []addrRange) addrSet {
	if len(ranges) == 0 {
		return addrSet{}
	}
	return addrSet{chunks: appendChunks(make([][]addrRange, 0, (len(ranges)+chunkSize-1)/chunkSize), ranges)}
}

func appendChunks(chunks [][]addrRange, ranges []addrRange) [][]addrRange {
	for len(ranges) > 0 {
		n := min(len(ranges), chunkSize)
		chunks = append(chunks, ranges[:n:n])
		ranges = ranges[n:]
	}
	return chunks
}

func setOfPrefix(prefix netip.Prefix) addrSet {
	prefix = prefix.Masked()
	return makeSet([]addrRange{{lo: prefix.Addr(), hi: lastAddr(prefix)}})
}

func setOfPrefixes(prefixes []netip.Prefix) addrSet {
	ranges := make([]addrRange, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		ranges = append(ranges, addrRange{lo: prefix.Addr(), hi: lastAddr(prefix)})
	}
	return normalizeRanges(ranges)
}

// normalizeRanges returns the set of arbitrary ranges: it sorts them and
// merges those that overlap or touch. The slice is reordered in place.
func normalizeRanges(ranges []addrRange) addrSet {
	if len(ranges) > 1 {
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo.Compare(ranges[j].lo) < 0 })
		merged := ranges[:1]
		for _, next := range ranges[1:] {
			if last := &merged[len(merged)-1]; touches(*last, next) {
				last.hi = maxAddr(last.hi, next.hi)
			} else {
				merged = append(merged, next)
			}
		}
		ranges = merged
	}
	return makeSet(ranges)
}

// lastAddr returns the highest address of a prefix.
func lastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	if addr.Is4() {
		b := addr.As4()
		setHostBits(b[:], prefix.Bits())
		return netip.AddrFrom4(b)
	}
	b := addr.As16()
	setHostBits(b[:], prefix.Bits())
	return netip.AddrFrom16(b)
}

func setHostBits(b []byte, prefixBits int) {
	for bit := prefixBits; bit < len(b)*8; bit++ {
		b[bit/8] |= 1 << (7 - uint(bit%8))
	}
}

func (s addrSet) empty() bool { return len(s.chunks) == 0 }

// ranges returns all ranges in ascending order. The result must not be
// modified: it can be a chunk of the set.
func (s addrSet) ranges() []addrRange {
	switch len(s.chunks) {
	case 0:
		return nil
	case 1:
		return s.chunks[0]
	}
	total := 0
	for _, chunk := range s.chunks {
		total += len(chunk)
	}
	all := make([]addrRange, 0, total)
	for _, chunk := range s.chunks {
		all = append(all, chunk...)
	}
	return all
}

// split divides the set into the addresses inside and outside a prefix.
func (s addrSet) split(prefix netip.Prefix) (inside, outside addrSet) {
	return s.splitRange(prefix.Masked().Addr(), lastAddr(prefix))
}

func (s addrSet) splitRange(lo, hi netip.Addr) (inside, outside addrSet) {
	// The chunks that can hold addresses of [lo, hi]: from the first one that
	// ends at or after lo, as long as they start at or before hi.
	first := sort.Search(len(s.chunks), func(i int) bool {
		chunk := s.chunks[i]
		return chunk[len(chunk)-1].hi.Compare(lo) >= 0
	})
	end := first
	for end < len(s.chunks) && s.chunks[end][0].lo.Compare(hi) <= 0 {
		end++
	}
	if first == end {
		return addrSet{}, s
	}
	var in, out []addrRange
	for _, chunk := range s.chunks[first:end] {
		for _, r := range chunk {
			if r.hi.Compare(lo) < 0 || r.lo.Compare(hi) > 0 {
				out = append(out, r)
				continue
			}
			if r.lo.Compare(lo) < 0 {
				out = append(out, addrRange{lo: r.lo, hi: lo.Prev()})
			}
			in = append(in, addrRange{lo: maxAddr(r.lo, lo), hi: minAddr(r.hi, hi)})
			if r.hi.Compare(hi) > 0 {
				out = append(out, addrRange{lo: hi.Next(), hi: r.hi})
			}
		}
	}
	switch {
	case len(in) == 0:
		return addrSet{}, s
	case len(out) == 0 && first == 0 && end == len(s.chunks):
		return s, addrSet{}
	}
	chunks := make([][]addrRange, 0, len(s.chunks)-(end-first)+len(out)/chunkSize+1)
	chunks = append(chunks, s.chunks[:first]...)
	chunks = appendChunks(chunks, out)
	chunks = append(chunks, s.chunks[end:]...)
	return makeSet(in), addrSet{chunks: chunks}
}

func minAddr(a, b netip.Addr) netip.Addr {
	if a.Compare(b) <= 0 {
		return a
	}
	return b
}

func maxAddr(a, b netip.Addr) netip.Addr {
	if a.Compare(b) >= 0 {
		return a
	}
	return b
}

// touches reports whether b starts inside a or directly after it.
func touches(a, b addrRange) bool {
	if b.lo.Compare(a.hi) <= 0 {
		return true
	}
	next := a.hi.Next()
	return next.IsValid() && next == b.lo
}

// union returns the addresses of either set.
func (s addrSet) union(other addrSet) addrSet {
	switch {
	case other.empty():
		return s
	case s.empty():
		return other
	}
	a, b := s.ranges(), other.ranges()
	merged := make([]addrRange, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		var next addrRange
		if j >= len(b) || (i < len(a) && a[i].lo.Compare(b[j].lo) <= 0) {
			next = a[i]
			i++
		} else {
			next = b[j]
			j++
		}
		if n := len(merged); n > 0 && touches(merged[n-1], next) {
			merged[n-1].hi = maxAddr(merged[n-1].hi, next.hi)
		} else {
			merged = append(merged, next)
		}
	}
	return makeSet(merged)
}

// subtract returns the addresses of s that are not in other.
func (s addrSet) subtract(other addrSet) addrSet {
	if s.empty() || other.empty() {
		return s
	}
	a, b := s.ranges(), other.ranges()
	result := make([]addrRange, 0, len(a))
	j := 0
	for _, r := range a {
		lo := r.lo
		covered := false
		for j < len(b) && b[j].hi.Compare(lo) < 0 {
			j++
		}
		for k := j; k < len(b) && b[k].lo.Compare(r.hi) <= 0; k++ {
			if b[k].lo.Compare(lo) > 0 {
				result = append(result, addrRange{lo: lo, hi: b[k].lo.Prev()})
			}
			if b[k].hi.Compare(r.hi) >= 0 {
				covered = true
				break
			}
			lo = b[k].hi.Next()
		}
		if !covered {
			result = append(result, addrRange{lo: lo, hi: r.hi})
		}
	}
	return makeSet(result)
}

// intersect returns the addresses of both sets.
func (s addrSet) intersect(other addrSet) addrSet {
	if s.empty() || other.empty() {
		return addrSet{}
	}
	a, b := s.ranges(), other.ranges()
	var result []addrRange
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		lo, hi := maxAddr(a[i].lo, b[j].lo), minAddr(a[i].hi, b[j].hi)
		if lo.Compare(hi) <= 0 {
			result = append(result, addrRange{lo: lo, hi: hi})
		}
		if a[i].hi.Compare(b[j].hi) < 0 {
			i++
		} else {
			j++
		}
	}
	return makeSet(result)
}

// overlaps reports whether the sets share an address.
func (s addrSet) overlaps(other addrSet) bool {
	if s.empty() || other.empty() {
		return false
	}
	a, b := s.ranges(), other.ranges()
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if maxAddr(a[i].lo, b[j].lo).Compare(minAddr(a[i].hi, b[j].hi)) <= 0 {
			return true
		}
		if a[i].hi.Compare(b[j].hi) < 0 {
			i++
		} else {
			j++
		}
	}
	return false
}

// overlapsPrefix reports whether the set has an address of the prefix. It
// does not build the two halves that split returns.
func (s addrSet) overlapsPrefix(prefix netip.Prefix) bool {
	lo, hi := prefix.Masked().Addr(), lastAddr(prefix)
	c := sort.Search(len(s.chunks), func(i int) bool {
		chunk := s.chunks[i]
		return chunk[len(chunk)-1].hi.Compare(lo) >= 0
	})
	if c == len(s.chunks) {
		return false
	}
	chunk := s.chunks[c]
	i := sort.Search(len(chunk), func(i int) bool { return chunk[i].hi.Compare(lo) >= 0 })
	return i < len(chunk) && chunk[i].lo.Compare(hi) <= 0
}

func (s addrSet) contains(addr netip.Addr) bool {
	return s.overlapsPrefix(netip.PrefixFrom(addr, addr.BitLen()))
}

func (s addrSet) equal(other addrSet) bool {
	a, b := s.ranges(), other.ranges()
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// u128 is an unsigned 128-bit number: the value of an address.
type u128 struct {
	hi, lo uint64
}

var maxU128 = u128{hi: ^uint64(0), lo: ^uint64(0)}

// addrValue returns the address as a number. IPv4 addresses are 32-bit values.
func addrValue(addr netip.Addr) u128 {
	if addr.Is4() {
		b := addr.As4()
		return u128{lo: uint64(binary.BigEndian.Uint32(b[:]))}
	}
	b := addr.As16()
	return u128{hi: binary.BigEndian.Uint64(b[:8]), lo: binary.BigEndian.Uint64(b[8:])}
}

func valueAddr(v u128, is4 bool) netip.Addr {
	if is4 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v.lo))
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], v.hi)
	binary.BigEndian.PutUint64(b[8:], v.lo)
	return netip.AddrFrom16(b)
}

func (a u128) less(b u128) bool {
	return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo)
}

// add returns a+b, or the maximum when the sum does not fit.
func (a u128) add(b u128) u128 {
	lo, carry := bits.Add64(a.lo, b.lo, 0)
	hi, carry := bits.Add64(a.hi, b.hi, carry)
	if carry != 0 {
		return maxU128
	}
	return u128{hi: hi, lo: lo}
}

func (a u128) sub(b u128) u128 {
	lo, borrow := bits.Sub64(a.lo, b.lo, 0)
	hi, _ := bits.Sub64(a.hi, b.hi, borrow)
	return u128{hi: hi, lo: lo}
}

// pow2 returns 2^n for n below 128.
func pow2(n int) u128 {
	if n >= 64 {
		return u128{hi: 1 << uint(n-64)}
	}
	return u128{lo: 1 << uint(n)}
}

func (a u128) trailingZeros() int {
	if a.lo != 0 {
		return bits.TrailingZeros64(a.lo)
	}
	return 64 + bits.TrailingZeros64(a.hi)
}

// bitLen returns the number of bits needed to write a.
func (a u128) bitLen() int {
	if a.hi != 0 {
		return 64 + bits.Len64(a.hi)
	}
	return bits.Len64(a.lo)
}

// size returns the number of addresses in the range, or the maximum for a
// whole IPv6 address space.
func (r addrRange) size() u128 {
	return addrValue(r.hi).sub(addrValue(r.lo)).add(u128{lo: 1})
}

// subtractSet returns the part of one range that is not in the set.
func (r addrRange) subtractSet(other addrSet) addrSet {
	return makeSet([]addrRange{r}).subtract(other)
}

// size returns the number of addresses in the set, saturating at the maximum.
func (s addrSet) size() u128 {
	var total u128
	for _, chunk := range s.chunks {
		for _, r := range chunk {
			total = total.add(r.size())
		}
	}
	return total
}

// prefixes returns the smallest list of prefixes that covers exactly the set.
func (s addrSet) prefixes() []netip.Prefix {
	var result []netip.Prefix
	for _, r := range s.ranges() {
		is4 := r.lo.Is4()
		width := 128
		if is4 {
			width = 32
		}
		cur, end := addrValue(r.lo), addrValue(r.hi)
		for {
			// The largest block that starts at cur: limited by the alignment
			// of cur and by the addresses left in the range.
			blockBits := min(cur.trailingZeros(), width)
			if left := end.sub(cur); left != maxU128 {
				blockBits = min(blockBits, left.add(u128{lo: 1}).bitLen()-1)
			}
			result = append(result, netip.PrefixFrom(valueAddr(cur, is4), width-blockBits))
			if blockBits >= width {
				break
			}
			last := cur.add(pow2(blockBits).sub(u128{lo: 1}))
			if !last.less(end) {
				break
			}
			cur = last.add(u128{lo: 1})
		}
	}
	return result
}
