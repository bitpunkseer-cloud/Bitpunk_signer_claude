//! Find and read a QR code in a greyscale camera frame. The pipeline
//! follows the well-proven ZXing design (Passport Prime uses its Rust
//! port): local block thresholds, finder patterns by 1:1:3:1:1 run ratios
//! with vertical / horizontal / diagonal cross-checks, the alignment
//! pattern for perspective, a four-point homography and grid sampling.
//! Written from the algorithm description; allocation-free.

use crate::decode::{self, BitMatrix, Decoded};

/// Largest frame accepted (the device camera delivers 640 x 480).
pub const MAX_WIDTH: usize = 1024;
pub const MAX_HEIGHT: usize = 1024;
const MIN_DIM: usize = 40;
const BLOCK: usize = 8;
const MAX_BLOCKS: usize = (MAX_WIDTH / BLOCK) * (MAX_HEIGHT / BLOCK);
const MIN_DYNAMIC_RANGE: i32 = 24;
const MAX_CANDIDATES: usize = 64;
const MAX_MODULES: usize = 97;
/// Run-ratio tolerance (module / this) for the cross-checks: a little
/// looser than the row scan because blur and thresholding thin the light
/// rings of the finder pattern.
const RECHECK_VARIANCE: f32 = 1.6;
/// Finder triples tried per frame and polarity, best first.
const TRIPLES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Point {
    pub x: f32,
    pub y: f32,
}

/// Greyscale frame, one byte per pixel, row-major.
#[derive(Clone, Copy)]
pub struct Image<'a> {
    data: &'a [u8],
    width: usize,
    height: usize,
}

impl<'a> Image<'a> {
    pub fn new(data: &'a [u8], width: usize, height: usize) -> Option<Self> {
        let ok = (MIN_DIM..=MAX_WIDTH).contains(&width)
            && (MIN_DIM..=MAX_HEIGHT).contains(&height)
            && data.len() >= width * height;
        ok.then_some(Self { data, width, height })
    }
}

/// A decoded symbol and where it was in the frame.
#[derive(Clone, Copy, Debug)]
pub struct Found {
    pub decoded: Decoded,
    /// Symbol corners in image coordinates: top-left, top-right,
    /// bottom-right, bottom-left (of the code, not of the frame).
    pub corners: [Point; 4],
    /// Found on the inverted image (light modules on dark ground).
    pub inverted: bool,
}

#[derive(Clone, Copy)]
struct Candidate {
    x: f32,
    y: f32,
    module: f32,
    count: u16,
}

struct Candidates {
    list: [Candidate; MAX_CANDIDATES],
    n: usize,
}

/// Reusable scanner state (about 37 KB; keep one per camera).
pub struct Scanner {
    black_points: [u8; MAX_BLOCKS],
    thresholds: [u8; MAX_BLOCKS],
    bw: usize,
    bh: usize,
    cands: Candidates,
    matrix: BitMatrix,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- small float helpers (no_std has no sqrt/round) ----------

fn sqrt(v: f32) -> f32 {
    if v <= 0.0 {
        return 0.0;
    }
    // bit-level first guess, then Newton steps
    let mut x = f32::from_bits((v.to_bits() >> 1) + 0x1FBD_1DF5);
    for _ in 0..3 {
        x = 0.5 * (x + v / x);
    }
    x
}

fn round(v: f32) -> i32 {
    if v >= 0.0 {
        (v + 0.5) as i32
    } else {
        (v - 0.5) as i32
    }
}

fn abs(v: f32) -> f32 {
    if v < 0.0 {
        -v
    } else {
        v
    }
}

fn distance(ax: f32, ay: f32, bx: f32, by: f32) -> f32 {
    sqrt((ax - bx) * (ax - bx) + (ay - by) * (ay - by))
}

#[cfg(test)]
fn dist(a: Point, b: Point) -> f32 {
    distance(a.x, a.y, b.x, b.y)
}

// ---------- binarised view ----------

struct Bin<'a> {
    img: Image<'a>,
    thresholds: &'a [u8],
    bw: usize,
    invert: bool,
}

impl Bin<'_> {
    #[inline]
    fn w(&self) -> i32 {
        self.img.width as i32
    }
    #[inline]
    fn h(&self) -> i32 {
        self.img.height as i32
    }
    /// True for a dark pixel (light one when inverted). Outside = light.
    #[inline]
    fn get(&self, x: i32, y: i32) -> bool {
        if x < 0 || y < 0 || x >= self.w() || y >= self.h() {
            return false;
        }
        let (x, y) = (x as usize, y as usize);
        let mut v = self.img.data[y * self.img.width + x];
        if self.invert {
            v = 255 - v;
        }
        let bx = (x / BLOCK).min(self.bw - 1);
        let by = y / BLOCK;
        let by = by.min(self.img.height.div_ceil(BLOCK) - 1);
        v <= self.thresholds[by * self.bw + bx]
    }
}

// ---------- perspective transform ----------

#[derive(Clone, Copy)]
struct Transform {
    a11: f32,
    a21: f32,
    a31: f32,
    a12: f32,
    a22: f32,
    a32: f32,
    a13: f32,
    a23: f32,
    a33: f32,
}

impl Transform {
    /// Unit square (0,0) (1,0) (1,1) (0,1) to the given quadrilateral.
    #[allow(clippy::too_many_arguments)]
    fn square_to_quad(x0: f32, y0: f32, x1: f32, y1: f32, x2: f32, y2: f32, x3: f32, y3: f32) -> Self {
        let dx3 = x0 - x1 + x2 - x3;
        let dy3 = y0 - y1 + y2 - y3;
        if dx3 == 0.0 && dy3 == 0.0 {
            return Self {
                a11: x1 - x0,
                a21: x2 - x1,
                a31: x0,
                a12: y1 - y0,
                a22: y2 - y1,
                a32: y0,
                a13: 0.0,
                a23: 0.0,
                a33: 1.0,
            };
        }
        let dx1 = x1 - x2;
        let dx2 = x3 - x2;
        let dy1 = y1 - y2;
        let dy2 = y3 - y2;
        let den = dx1 * dy2 - dx2 * dy1;
        let a13 = (dx3 * dy2 - dx2 * dy3) / den;
        let a23 = (dx1 * dy3 - dx3 * dy1) / den;
        Self {
            a11: x1 - x0 + a13 * x1,
            a21: x3 - x0 + a23 * x3,
            a31: x0,
            a12: y1 - y0 + a13 * y1,
            a22: y3 - y0 + a23 * y3,
            a32: y0,
            a13,
            a23,
            a33: 1.0,
        }
    }

    fn adjoint(&self) -> Self {
        Self {
            a11: self.a22 * self.a33 - self.a23 * self.a32,
            a21: self.a23 * self.a31 - self.a21 * self.a33,
            a31: self.a21 * self.a32 - self.a22 * self.a31,
            a12: self.a13 * self.a32 - self.a12 * self.a33,
            a22: self.a11 * self.a33 - self.a13 * self.a31,
            a32: self.a12 * self.a31 - self.a11 * self.a32,
            a13: self.a12 * self.a23 - self.a13 * self.a22,
            a23: self.a13 * self.a21 - self.a11 * self.a23,
            a33: self.a11 * self.a22 - self.a12 * self.a21,
        }
    }

    fn times(&self, o: &Self) -> Self {
        Self {
            a11: self.a11 * o.a11 + self.a21 * o.a12 + self.a31 * o.a13,
            a21: self.a11 * o.a21 + self.a21 * o.a22 + self.a31 * o.a23,
            a31: self.a11 * o.a31 + self.a21 * o.a32 + self.a31 * o.a33,
            a12: self.a12 * o.a11 + self.a22 * o.a12 + self.a32 * o.a13,
            a22: self.a12 * o.a21 + self.a22 * o.a22 + self.a32 * o.a23,
            a32: self.a12 * o.a31 + self.a22 * o.a32 + self.a32 * o.a33,
            a13: self.a13 * o.a11 + self.a23 * o.a12 + self.a33 * o.a13,
            a23: self.a13 * o.a21 + self.a23 * o.a22 + self.a33 * o.a23,
            a33: self.a13 * o.a31 + self.a23 * o.a32 + self.a33 * o.a33,
        }
    }

    /// Map quadrilateral `from` onto quadrilateral `to` (corners in the
    /// order of the unit square).
    fn quad_to_quad(from: [Point; 4], to: [Point; 4]) -> Self {
        let q2s = Self::square_to_quad(
            from[0].x, from[0].y, from[1].x, from[1].y, from[2].x, from[2].y, from[3].x, from[3].y,
        )
        .adjoint();
        let s2q = Self::square_to_quad(
            to[0].x, to[0].y, to[1].x, to[1].y, to[2].x, to[2].y, to[3].x, to[3].y,
        );
        s2q.times(&q2s)
    }

    fn apply(&self, x: f32, y: f32) -> Point {
        let den = self.a13 * x + self.a23 * y + self.a33;
        Point {
            x: (self.a11 * x + self.a21 * y + self.a31) / den,
            y: (self.a12 * x + self.a22 * y + self.a32) / den,
        }
    }
}

// ---------- run-ratio checks ----------

fn finder_cross(c: &[i32; 5], variance_div: f32) -> bool {
    let total: i32 = c.iter().sum();
    if total < 7 || c.contains(&0) {
        return false;
    }
    let m = total as f32 / 7.0;
    let v = m / variance_div;
    abs(m - c[0] as f32) < v
        && abs(m - c[1] as f32) < v
        && abs(3.0 * m - c[2] as f32) < 3.0 * v
        && abs(m - c[3] as f32) < v
        && abs(m - c[4] as f32) < v
}

fn center_from_end(c: &[i32; 5], end: i32) -> f32 {
    (end - c[4] - c[3]) as f32 - c[2] as f32 / 2.0
}

impl Scanner {
    pub const fn new() -> Self {
        Self {
            black_points: [0; MAX_BLOCKS],
            thresholds: [0; MAX_BLOCKS],
            bw: 0,
            bh: 0,
            cands: Candidates {
                list: [Candidate {
                    x: 0.0,
                    y: 0.0,
                    module: 0.0,
                    count: 0,
                }; MAX_CANDIDATES],
                n: 0,
            },
            matrix: BitMatrix::empty(),
        }
    }

    /// Read one QR code from `img` into `out`. Tries the normal image,
    /// then the inverted one.
    pub fn scan(&mut self, img: Image, out: &mut [u8]) -> Option<Found> {
        for invert in [false, true] {
            self.binarize(img, invert);
            if let Some(f) = self.scan_binarized(img, invert, out) {
                return Some(f);
            }
        }
        None
    }

    // ---------- local thresholds (8x8 blocks, 5x5 block average) ----------

    fn binarize(&mut self, img: Image, invert: bool) {
        let (w, h) = (img.width, img.height);
        let bw = w.div_ceil(BLOCK);
        let bh = h.div_ceil(BLOCK);
        self.bw = bw;
        self.bh = bh;
        for by in 0..bh {
            let yoff = (by * BLOCK).min(h - BLOCK);
            for bx in 0..bw {
                let xoff = (bx * BLOCK).min(w - BLOCK);
                let (mut sum, mut min, mut max) = (0i32, 255i32, 0i32);
                for yy in 0..BLOCK {
                    let row = &img.data[(yoff + yy) * w + xoff..(yoff + yy) * w + xoff + BLOCK];
                    for &p in row {
                        let p = if invert { 255 - p as i32 } else { p as i32 };
                        sum += p;
                        min = min.min(p);
                        max = max.max(p);
                    }
                }
                let mut avg = sum >> 6;
                if max - min <= MIN_DYNAMIC_RANGE {
                    // flat block: assume light unless the neighbours say
                    // it sits inside a dark area
                    avg = min / 2;
                    if by > 0 && bx > 0 {
                        let up = self.black_points[(by - 1) * bw + bx] as i32;
                        let left = self.black_points[by * bw + bx - 1] as i32;
                        let diag = self.black_points[(by - 1) * bw + bx - 1] as i32;
                        let nb = (up + 2 * left + diag) / 4;
                        if min < nb {
                            avg = nb;
                        }
                    }
                }
                self.black_points[by * bw + bx] = avg as u8;
            }
        }
        for by in 0..bh {
            let top = by.clamp(2, bh - 3);
            for bx in 0..bw {
                let left = bx.clamp(2, bw - 3);
                let mut sum = 0u32;
                for yy in top - 2..=top + 2 {
                    for xx in left - 2..=left + 2 {
                        sum += self.black_points[yy * bw + xx] as u32;
                    }
                }
                self.thresholds[by * bw + bx] = (sum / 25) as u8;
            }
        }
    }

    fn scan_binarized(&mut self, img: Image, invert: bool, out: &mut [u8]) -> Option<Found> {
        let bin = Bin {
            img,
            thresholds: &self.thresholds,
            bw: self.bw,
            invert,
        };
        self.cands.find(&bin);
        let mut triples = [[0usize; 3]; TRIPLES];
        let n = self.cands.best_triples(&mut triples);
        for t in &triples[..n] {
            let pts = self.cands.order([t[0], t[1], t[2]]);
            if let Some(f) = detect_and_decode(&mut self.matrix, &bin, pts, out) {
                return Some(Found {
                    inverted: invert,
                    ..f
                });
            }
        }
        None
    }
}

impl Candidates {
    // ---------- finder patterns ----------

    fn find(&mut self, b: &Bin) {
        self.n = 0;
        let (w, h) = (b.w(), b.h());
        let skip = ((3 * h as usize) / (4 * MAX_MODULES)).max(3) as i32;
        let mut i = skip - 1;
        while i < h {
            let mut c = [0i32; 5];
            let mut state = 0usize;
            let mut j = 0;
            while j < w {
                if b.get(j, i) {
                    if state & 1 == 1 {
                        state += 1;
                    }
                    c[state] += 1;
                } else if state & 1 == 0 {
                    if state == 4 {
                        if finder_cross(&c, 2.0) && self.handle(b, &c, i, j) {
                            state = 0;
                            c = [0; 5];
                        } else {
                            c = [c[2], c[3], c[4], 1, 0];
                            state = 3;
                        }
                    } else {
                        state += 1;
                        c[state] += 1;
                    }
                } else {
                    c[state] += 1;
                }
                j += 1;
            }
            if finder_cross(&c, 2.0) {
                self.handle(b, &c, i, w);
            }
            i += skip;
        }
    }

    fn handle(&mut self, b: &Bin, c: &[i32; 5], i: i32, j: i32) -> bool {
        let total: i32 = c.iter().sum();
        let cj = center_from_end(c, j);
        let Some(ci) = cross_check_vertical(b, i, cj as i32, c[2], total) else {
            return false;
        };
        let Some(cj) = cross_check_horizontal(b, cj as i32, ci as i32, c[2], total) else {
            return false;
        };
        if !cross_check_diagonal(b, ci as i32, cj as i32) {
            return false;
        }
        let module = total as f32 / 7.0;
        for cand in self.list.iter_mut().take(self.n) {
            if abs(ci - cand.y) <= module && abs(cj - cand.x) <= module {
                let diff = abs(module - cand.module);
                if diff <= 1.0 || diff <= cand.module {
                    let n = cand.count as f32;
                    cand.x = (n * cand.x + cj) / (n + 1.0);
                    cand.y = (n * cand.y + ci) / (n + 1.0);
                    cand.module = (n * cand.module + module) / (n + 1.0);
                    cand.count = cand.count.saturating_add(1);
                    return true;
                }
            }
        }
        if self.n < MAX_CANDIDATES {
            self.list[self.n] = Candidate {
                x: cj,
                y: ci,
                module,
                count: 1,
            };
            self.n += 1;
        }
        true
    }

    /// Up to `TRIPLES` finder triples, most like an isosceles right
    /// triangle first, among candidates of similar module size.
    fn best_triples(&self, out: &mut [[usize; 3]; TRIPLES]) -> usize {
        let n = self.n;
        if n < 3 {
            return 0;
        }
        // prefer confirmed candidates when there are enough of them
        let confirmed = self.list[..n].iter().filter(|c| c.count >= 2).count();
        let min_count = if confirmed >= 3 { 2 } else { 1 };
        let mut scores = [f32::MAX; TRIPLES];
        let mut found = 0;
        for i in 0..n {
            let ci = self.list[i];
            if ci.count < min_count {
                continue;
            }
            for j in i + 1..n {
                let cj = self.list[j];
                if cj.count < min_count {
                    continue;
                }
                for k in j + 1..n {
                    let ck = self.list[k];
                    if ck.count < min_count {
                        continue;
                    }
                    let lo = ci.module.min(cj.module).min(ck.module);
                    let hi = ci.module.max(cj.module).max(ck.module);
                    if hi > lo * 1.4 {
                        continue;
                    }
                    let sq =
                        |a: Candidate, b: Candidate| (a.x - b.x) * (a.x - b.x) + (a.y - b.y) * (a.y - b.y);
                    let mut d = [sq(ci, cj), sq(cj, ck), sq(ci, ck)];
                    d.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal));
                    let (a, bb, c) = (d[0], d[1], d[2]);
                    // finder centres are at least 14 modules apart
                    let m = (ci.module + cj.module + ck.module) / 3.0;
                    if a < (14.0 * m) * (14.0 * m) * 0.5 {
                        continue;
                    }
                    let score = (abs(c - 2.0 * bb) + abs(c - 2.0 * a)) / c;
                    // insert into the sorted top list
                    let mut pos = found.min(TRIPLES);
                    while pos > 0 && scores[pos - 1] > score {
                        pos -= 1;
                    }
                    if pos < TRIPLES {
                        let mut q = TRIPLES - 1;
                        while q > pos {
                            scores[q] = scores[q - 1];
                            out[q] = out[q - 1];
                            q -= 1;
                        }
                        scores[pos] = score;
                        out[pos] = [i, j, k];
                        found = (found + 1).min(TRIPLES);
                    }
                }
            }
        }
        found
    }

    /// Order as [bottom-left, top-left, top-right].
    fn order(&self, idx: [usize; 3]) -> [Candidate; 3] {
        let p = idx.map(|i| self.list[i]);
        let d = |a: Candidate, b: Candidate| distance(a.x, a.y, b.x, b.y);
        let (d01, d12, d02) = (d(p[0], p[1]), d(p[1], p[2]), d(p[0], p[2]));
        let (mut a, b, mut c) = if d12 >= d01 && d12 >= d02 {
            (p[1], p[0], p[2])
        } else if d02 >= d12 && d02 >= d01 {
            (p[0], p[1], p[2])
        } else {
            (p[0], p[2], p[1])
        };
        let cross = (c.x - b.x) * (a.y - b.y) - (c.y - b.y) * (a.x - b.x);
        if cross < 0.0 {
            core::mem::swap(&mut a, &mut c);
        }
        [a, b, c]
    }
}

// ---------- geometry and sampling ----------

fn detect_and_decode(matrix: &mut BitMatrix, b: &Bin, p: [Candidate; 3], out: &mut [u8]) -> Option<Found> {
    let [bl, tl, tr] = p;
    let module = module_size(b, tl, tr, bl);
    if module < 1.0 {
        return None;
    }
    let d1 = round(distance(tl.x, tl.y, tr.x, tr.y) / module);
    let d2 = round(distance(tl.x, tl.y, bl.x, bl.y) / module);
    let base = (d1 + d2) / 2 + 7;
    // the nominal size, then its neighbours
    let first = match base & 3 {
        0 => base + 1,
        2 => base - 1,
        3 => base + 2,
        _ => base,
    };
    // Size candidates, most trusted first: the version information
    // blocks read from the image (version 7+), the timing pattern count,
    // then the size from the finder distance and its neighbours.
    let mut dims = [0i32; 6];
    let mut nd = 0;
    let add = |d: i32, dims: &mut [i32; 6], nd: &mut usize| {
        if (21..=177).contains(&d) && (d - 17) % 4 == 0 && !dims[..*nd].contains(&d) && *nd < 6 {
            dims[*nd] = d;
            *nd += 1;
        }
    };
    if first >= 41 {
        if let Some(v) = read_version_info(b, tl, tr, bl) {
            add(17 + 4 * v as i32, &mut dims, &mut nd);
        }
    }
    if let Some(t) = timing_dimension(b, tl, tr, bl) {
        if (t - first).abs() <= 12 {
            add(t, &mut dims, &mut nd);
        }
    }
    for d in [first, first - 4, first + 4] {
        add(d, &mut dims, &mut nd);
    }
    for &dim in &dims[..nd] {
        let dim = dim as usize;
        let tlp = Point { x: tl.x, y: tl.y };
        let trp = Point { x: tr.x, y: tr.y };
        let blp = Point { x: bl.x, y: bl.y };
        // cheap gate: the format information next to the finders must be
        // readable (parallelogram or projective corner) before the costly
        // alignment search and refinement
        let est0 = Point {
            x: trp.x - tlp.x + blp.x,
            y: trp.y - tlp.y + blp.y,
        };
        let w1 = sqrt(tl.module / tr.module.max(0.5));
        let w2 = sqrt(tl.module / bl.module.max(0.5));
        let proj0 = Point {
            x: (w1 * trp.x + w2 * blp.x - tlp.x) / (w1 + w2 - 1.0),
            y: (w1 * trp.y + w2 * blp.y - tlp.y) / (w1 + w2 - 1.0),
        };
        let readable = [est0, proj0]
            .iter()
            .any(|&c| format_readable(b, &corner_transform([tlp, trp, c, blp], dim), dim));
        if !readable {
            continue;
        }
        let align = if dim > 21 {
            find_alignment(b, tlp, trp, blp, module, dim)
        } else {
            None
        };
        // bottom-right reference: the alignment pattern, the estimated
        // corner, then (no alignment pattern found) a small search around
        // the estimate to absorb perspective
        let est = Point {
            x: trp.x - tlp.x + blp.x,
            y: trp.y - tlp.y + blp.y,
        };
        let between = dim as f32 - 7.0;
        let u = Point {
            x: (trp.x - tlp.x) / between,
            y: (trp.y - tlp.y) / between,
        };
        let v = Point {
            x: (blp.x - tlp.x) / between,
            y: (blp.y - tlp.y) / between,
        };
        const STEPS: [f32; 5] = [0.0, -0.75, 0.75, -1.5, 1.5];
        let dm3 = dim as f32 - 3.5;
        // Candidates for the bottom-right reference, in order: the
        // run-length alignment pattern, a template match of the alignment
        // pattern near its predicted place, the estimated corner, and for
        // version 1 (no alignment pattern) a grid around the estimate.
        let mut refs: [(Point, f32); 28] = [(est, dm3); 28];
        let mut refined_all: Option<[Point; 4]> = None;
        let mut nref = 0;
        if let Some(a) = align {
            refs[nref] = (a, dm3 - 3.0);
            nref += 1;
        }
        if dim > 21 {
            let t_est = Transform::quad_to_quad(
                [
                    Point { x: 3.5, y: 3.5 },
                    Point { x: dm3, y: 3.5 },
                    Point { x: dm3, y: dm3 },
                    Point { x: 3.5, y: dm3 },
                ],
                [tlp, trp, est, blp],
            );
            if let Some(a) = match_alignment(b, &t_est, dim) {
                if align.is_none_or(|p| distance(p.x, p.y, a.x, a.y) > 1.0) {
                    refs[nref] = (a, dm3 - 3.0);
                    nref += 1;
                }
            }
        }
        refs[nref] = (est, dm3);
        nref += 1;
        if dim > 21 {
            // pattern-fitness refinement of the corner (perspective)
            let start = refs[0];
            let corner = if start.1 == dm3 {
                start.0
            } else {
                // alignment centre -> virtual corner at (dm3, dm3)
                let t = Transform::quad_to_quad(
                    [
                        Point { x: 3.5, y: 3.5 },
                        Point { x: dm3, y: 3.5 },
                        Point {
                            x: start.1,
                            y: start.1,
                        },
                        Point { x: 3.5, y: dm3 },
                    ],
                    [tlp, trp, start.0, blp],
                );
                t.apply(dm3, dm3)
            };
            // projective estimate from the finders' apparent sizes: with
            // w = 1 + g x + h y, module size scales with 1 / w^2
            let w1 = sqrt(tl.module / tr.module.max(0.5));
            let w2 = sqrt(tl.module / bl.module.max(0.5));
            let den = w1 + w2 - 1.0;
            let proj = Point {
                x: (w1 * trp.x + w2 * blp.x - tlp.x) / den,
                y: (w1 * trp.y + w2 * blp.y - tlp.y) / den,
            };
            // start from whichever fits the patterns best
            let mut c0 = [tlp, trp, corner, blp];
            for cand in [est, proj] {
                let c = [tlp, trp, cand, blp];
                if pattern_fitness(b, c, dim) > pattern_fitness(b, c0, dim) {
                    c0 = c;
                }
            }
            let c1 = refine(b, c0, &[2], dim, module, 2.0);
            refs[nref] = (c1[2], dm3);
            nref += 1;
            refined_all = Some(refine(b, c1, &[0, 1, 2, 3], dim, module, 0.5));
        }
        if dim == 21 {
            for k in 1..25 {
                let (du, dv) = (STEPS[k % 5], STEPS[k / 5]);
                refs[nref] = (
                    Point {
                        x: est.x + du * u.x + dv * v.x,
                        y: est.y + du * u.y + dv * v.y,
                    },
                    dm3,
                );
                nref += 1;
            }
        }
        for &(br, src_br) in &refs[..nref] {
            let t = Transform::quad_to_quad(
                [
                    Point { x: 3.5, y: 3.5 },
                    Point { x: dm3, y: 3.5 },
                    Point { x: src_br, y: src_br },
                    Point { x: 3.5, y: dm3 },
                ],
                [tlp, trp, br, blp],
            );
            if let Some(f) = try_decode(matrix, b, &t, dim, out) {
                return Some(f);
            }
        }
        if let Some(c) = refined_all {
            if let Some(f) = try_decode(matrix, b, &corner_transform(c, dim), dim, out) {
                return Some(f);
            }
        }
    }
    None
}

/// Sample just the 30 format-information modules under `t` (also at
/// transposed positions, for mirrored symbols) and apply the strict gate.
fn format_readable(b: &Bin, t: &Transform, dim: usize) -> bool {
    let bit = |x: usize, y: usize| -> u32 {
        let p = t.apply(x as f32 + 0.5, y as f32 + 0.5);
        b.get(p.x as i32, p.y as i32) as u32
    };
    let (mut a, mut c, mut ta, mut tc) = (0u32, 0u32, 0u32, 0u32);
    for i in 0..15 {
        let ((x1, y1), (x2, y2)) = decode::format_positions(dim, i);
        a |= bit(x1, y1) << i;
        c |= bit(x2, y2) << i;
        ta |= bit(y1, x1) << i;
        tc |= bit(y2, x2) << i;
    }
    decode::format_gate(a, c) || decode::format_gate(ta, tc)
}

fn try_decode(matrix: &mut BitMatrix, b: &Bin, t: &Transform, dim: usize, out: &mut [u8]) -> Option<Found> {
    if !sample(matrix, b, t, dim) {
        return None;
    }
    let d = decode::decode(matrix, out).ok()?;
    let n = dim as f32;
    Some(Found {
        decoded: d,
        corners: [t.apply(0.0, 0.0), t.apply(n, 0.0), t.apply(n, n), t.apply(0.0, n)],
        inverted: false,
    })
}

/// Sample module centres into `matrix`; false if the grid falls outside
/// the image.
fn sample(matrix: &mut BitMatrix, b: &Bin, t: &Transform, dim: usize) -> bool {
    if !matrix.reset(dim) {
        return false;
    }
    let (w, h) = (b.w() as f32, b.h() as f32);
    for y in 0..dim {
        for x in 0..dim {
            let p = t.apply(x as f32 + 0.5, y as f32 + 0.5);
            if !(p.x > -1.0 && p.y > -1.0 && p.x < w + 1.0 && p.y < h + 1.0) || p.x.is_nan() || p.y.is_nan() {
                return false;
            }
            // nudge points just outside the frame onto its edge
            let ix = (p.x as i32).clamp(0, b.w() - 1);
            let iy = (p.y as i32).clamp(0, b.h() - 1);
            if b.get(ix, iy) {
                matrix.set(x, y, true);
            }
        }
    }
    true
}

fn cross_check_vertical(b: &Bin, start_i: i32, cj: i32, max_count: i32, orig_total: i32) -> Option<f32> {
    let h = b.h();
    let mut c = [0i32; 5];
    let mut i = start_i;
    while i >= 0 && b.get(cj, i) {
        c[2] += 1;
        i -= 1;
    }
    if i < 0 {
        return None;
    }
    while i >= 0 && !b.get(cj, i) && c[1] <= max_count {
        c[1] += 1;
        i -= 1;
    }
    if i < 0 || c[1] > max_count {
        return None;
    }
    while i >= 0 && b.get(cj, i) && c[0] <= max_count {
        c[0] += 1;
        i -= 1;
    }
    if c[0] > max_count {
        return None;
    }
    i = start_i + 1;
    while i < h && b.get(cj, i) {
        c[2] += 1;
        i += 1;
    }
    if i == h {
        return None;
    }
    while i < h && !b.get(cj, i) && c[3] < max_count {
        c[3] += 1;
        i += 1;
    }
    if i == h || c[3] >= max_count {
        return None;
    }
    while i < h && b.get(cj, i) && c[4] < max_count {
        c[4] += 1;
        i += 1;
    }
    if c[4] >= max_count {
        return None;
    }
    let total: i32 = c.iter().sum();
    if 5 * (total - orig_total).abs() >= 2 * orig_total {
        return None;
    }
    finder_cross(&c, RECHECK_VARIANCE).then(|| center_from_end(&c, i))
}

fn cross_check_horizontal(b: &Bin, start_j: i32, ci: i32, max_count: i32, orig_total: i32) -> Option<f32> {
    let w = b.w();
    let mut c = [0i32; 5];
    let mut j = start_j;
    while j >= 0 && b.get(j, ci) {
        c[2] += 1;
        j -= 1;
    }
    if j < 0 {
        return None;
    }
    while j >= 0 && !b.get(j, ci) && c[1] <= max_count {
        c[1] += 1;
        j -= 1;
    }
    if j < 0 || c[1] > max_count {
        return None;
    }
    while j >= 0 && b.get(j, ci) && c[0] <= max_count {
        c[0] += 1;
        j -= 1;
    }
    if c[0] > max_count {
        return None;
    }
    j = start_j + 1;
    while j < w && b.get(j, ci) {
        c[2] += 1;
        j += 1;
    }
    if j == w {
        return None;
    }
    while j < w && !b.get(j, ci) && c[3] < max_count {
        c[3] += 1;
        j += 1;
    }
    if j == w || c[3] >= max_count {
        return None;
    }
    while j < w && b.get(j, ci) && c[4] < max_count {
        c[4] += 1;
        j += 1;
    }
    if c[4] >= max_count {
        return None;
    }
    let total: i32 = c.iter().sum();
    if 5 * (total - orig_total).abs() >= orig_total {
        return None;
    }
    finder_cross(&c, RECHECK_VARIANCE).then(|| center_from_end(&c, j))
}

fn cross_check_diagonal(b: &Bin, ci: i32, cj: i32) -> bool {
    let (w, h) = (b.w(), b.h());
    let mut c = [0i32; 5];
    let mut i = 0;
    while ci >= i && cj >= i && b.get(cj - i, ci - i) {
        c[2] += 1;
        i += 1;
    }
    if c[2] == 0 {
        return false;
    }
    while ci >= i && cj >= i && !b.get(cj - i, ci - i) {
        c[1] += 1;
        i += 1;
    }
    if c[1] == 0 {
        return false;
    }
    while ci >= i && cj >= i && b.get(cj - i, ci - i) {
        c[0] += 1;
        i += 1;
    }
    if c[0] == 0 {
        return false;
    }
    i = 1;
    while ci + i < h && cj + i < w && b.get(cj + i, ci + i) {
        c[2] += 1;
        i += 1;
    }
    while ci + i < h && cj + i < w && !b.get(cj + i, ci + i) {
        c[3] += 1;
        i += 1;
    }
    if c[3] == 0 {
        return false;
    }
    while ci + i < h && cj + i < w && b.get(cj + i, ci + i) {
        c[4] += 1;
        i += 1;
    }
    if c[4] == 0 {
        return false;
    }
    finder_cross(&c, 1.333)
}

// ---------- size from the symbol itself ----------

/// Unit vector from `a` to `b`.
fn unit(a: Candidate, b: Candidate) -> Point {
    let d = distance(a.x, a.y, b.x, b.y).max(1e-3);
    Point {
        x: (b.x - a.x) / d,
        y: (b.y - a.y) / d,
    }
}

/// Read the two version information blocks next to the top-right and
/// bottom-left finders, using each finder's own module size.
fn read_version_info(b: &Bin, tl: Candidate, tr: Candidate, bl: Candidate) -> Option<u8> {
    let ux = unit(tl, tr);
    let vy = unit(tl, bl);
    let block = |f: Candidate, transposed: bool| -> (u8, u32) {
        let m = f.module;
        let mut bits = 0u32;
        for i in 0..18 {
            // module offsets from the finder centre
            let (a, c) = ((i % 3) as f32 - 7.0, (i / 3) as f32 - 3.0);
            let (dx, dy) = if transposed { (c, a) } else { (a, c) };
            let x = f.x + (dx * ux.x + dy * vy.x) * m;
            let y = f.y + (dx * ux.y + dy * vy.y) * m;
            if b.get(round(x), round(y)) {
                bits |= 1 << i;
            }
        }
        decode::nearest_version(bits)
    };
    let (v1, d1) = block(tr, false);
    let (v2, d2) = block(bl, true);
    match (d1 <= 3, d2 <= 3) {
        (true, true) if v1 == v2 => Some(v1),
        (true, true) => Some(if d1 <= d2 { v1 } else { v2 }),
        (true, false) => Some(v1),
        (false, true) => Some(v2),
        _ => None,
    }
}

/// Count the timing pattern between two finders (row / column 6): the
/// number of light/dark runs from one finder centre to the other is the
/// symbol size minus 12.
fn timing_runs(b: &Bin, from: Candidate, to: Candidate, side: Point) -> Option<i32> {
    // timing row is 3 modules from the finder centres (centre 3.5, row 6.5)
    let p0 = Point {
        x: from.x + 3.0 * from.module * side.x,
        y: from.y + 3.0 * from.module * side.y,
    };
    let p1 = Point {
        x: to.x + 3.0 * to.module * side.x,
        y: to.y + 3.0 * to.module * side.y,
    };
    let len = distance(p0.x, p0.y, p1.x, p1.y);
    let steps = (len * 2.0) as i32;
    if steps < 8 {
        return None;
    }
    let m = (from.module + to.module) / 2.0;
    let min_run = (m * 2.0 * 0.4) as i32; // in half-pixel steps
    let mut runs = 0;
    let mut cur = None;
    let mut len_run = 0;
    let mut pending: Option<(bool, i32)> = None;
    for k in 0..=steps {
        let t = k as f32 / steps as f32;
        let x = p0.x + (p1.x - p0.x) * t;
        let y = p0.y + (p1.y - p0.y) * t;
        let v = b.get(round(x), round(y));
        match cur {
            Some(c) if c == v => len_run += 1,
            _ => {
                if let Some(c) = cur {
                    // ignore runs too short to be a module (noise)
                    if len_run >= min_run.max(1) && pending.is_none_or(|(pc, _)| pc != c) {
                        runs += 1;
                        pending = Some((c, len_run));
                    }
                }
                cur = Some(v);
                len_run = 1;
            }
        }
    }
    if let Some(c) = cur {
        if len_run >= min_run.max(1) && pending.is_none_or(|(pc, _)| pc != c) {
            runs += 1;
        }
    }
    Some(runs)
}

fn timing_dimension(b: &Bin, tl: Candidate, tr: Candidate, bl: Candidate) -> Option<i32> {
    let h = timing_runs(b, tl, tr, unit(tl, bl))?;
    let v = timing_runs(b, tl, bl, unit(tl, tr))?;
    let (dh, dv) = (h + 12, v + 12);
    let ok = |d: i32| (21..=177).contains(&d) && (d - 17) % 4 == 0;
    match (ok(dh), ok(dv)) {
        (true, true) if dh == dv => Some(dh),
        (true, false) => Some(dh),
        (false, true) => Some(dv),
        _ => None,
    }
}

// ---------- module size along the finder-to-finder lines ----------

fn module_size(b: &Bin, tl: Candidate, tr: Candidate, bl: Candidate) -> f32 {
    (module_one_way(b, tl, tr) + module_one_way(b, tl, bl)) / 2.0
}

fn module_one_way(b: &Bin, p: Candidate, q: Candidate) -> f32 {
    let e1 = bwb_both_ways(b, p.x as i32, p.y as i32, q.x as i32, q.y as i32);
    let e2 = bwb_both_ways(b, q.x as i32, q.y as i32, p.x as i32, p.y as i32);
    match (e1, e2) {
        (None, None) => (p.module + q.module) / 2.0,
        (Some(a), None) | (None, Some(a)) => a / 7.0,
        (Some(a), Some(c)) => (a + c) / 14.0,
    }
}

/// Length of the black-white-black run through a finder centre, measured
/// towards another finder and away from it.
fn bwb_both_ways(b: &Bin, fx: i32, fy: i32, tx: i32, ty: i32) -> Option<f32> {
    let first = bwb_run(b, fx, fy, tx, ty)?;
    let (w, h) = (b.w(), b.h());
    let mut scale = 1.0f32;
    let mut ox = fx - (tx - fx);
    if ox < 0 {
        scale = fx as f32 / (fx - ox) as f32;
        ox = 0;
    } else if ox >= w {
        scale = (w - 1 - fx) as f32 / (ox - fx) as f32;
        ox = w - 1;
    }
    let mut oy = (fy as f32 - (ty - fy) as f32 * scale) as i32;
    scale = 1.0;
    if oy < 0 {
        scale = fy as f32 / (fy - oy) as f32;
        oy = 0;
    } else if oy >= h {
        scale = (h - 1 - fy) as f32 / (oy - fy) as f32;
        oy = h - 1;
    }
    let ox = (fx as f32 + (ox - fx) as f32 * scale) as i32;
    let second = bwb_run(b, fx, fy, ox, oy)?;
    Some(first + second - 1.0)
}

fn bwb_run(b: &Bin, from_x: i32, from_y: i32, to_x: i32, to_y: i32) -> Option<f32> {
    let steep = (to_y - from_y).abs() > (to_x - from_x).abs();
    let (fx, fy, tx, ty) = if steep {
        (from_y, from_x, to_y, to_x)
    } else {
        (from_x, from_y, to_x, to_y)
    };
    let dx = (tx - fx).abs();
    let dy = (ty - fy).abs();
    let mut err = -dx / 2;
    let xstep = if fx < tx { 1 } else { -1 };
    let ystep = if fy < ty { 1 } else { -1 };
    let mut state = 0;
    let x_limit = tx + xstep;
    let mut x = fx;
    let mut y = fy;
    while x != x_limit {
        let (rx, ry) = if steep { (y, x) } else { (x, y) };
        if (state == 1) == b.get(rx, ry) {
            if state == 2 {
                return Some(distance(x as f32, y as f32, fx as f32, fy as f32));
            }
            state += 1;
        }
        err += dy;
        if err > 0 {
            if y == ty {
                break;
            }
            y += ystep;
            err -= dx;
        }
        x += xstep;
    }
    (state == 2).then(|| distance((tx + xstep) as f32, ty as f32, fx as f32, fy as f32))
}

// ---------- alignment pattern ----------

fn find_alignment(b: &Bin, tl: Point, tr: Point, bl: Point, module: f32, dim: usize) -> Option<Point> {
    let between = dim as f32 - 7.0;
    let br_x = tr.x - tl.x + bl.x;
    let br_y = tr.y - tl.y + bl.y;
    let corr = 1.0 - 3.0 / between;
    let ex = (tl.x + corr * (br_x - tl.x)) as i32;
    let ey = (tl.y + corr * (br_y - tl.y)) as i32;
    let mut factor = 4;
    while factor <= 16 {
        let allowance = (factor as f32 * module) as i32;
        let left = (ex - allowance).max(0);
        let right = (ex + allowance).min(b.w() - 1);
        let top = (ey - allowance).max(0);
        let bottom = (ey + allowance).min(b.h() - 1);
        if ((right - left) as f32) >= module * 3.0 && ((bottom - top) as f32) >= module * 3.0 {
            if let Some(p) = alignment_in_region(b, left, top, right - left, bottom - top, module) {
                return Some(p);
            }
        }
        factor <<= 1;
    }
    None
}

/// Transform from module coordinates for the four virtual corners
/// (finder centres and the matching bottom-right point).
fn corner_transform(c: [Point; 4], dim: usize) -> Transform {
    let dm3 = dim as f32 - 3.5;
    Transform::quad_to_quad(
        [
            Point { x: 3.5, y: 3.5 },
            Point { x: dm3, y: 3.5 },
            Point { x: dm3, y: dm3 },
            Point { x: 3.5, y: dm3 },
        ],
        c,
    )
}

/// How well the finder, timing and alignment patterns sit under the
/// transform given by corners [tl, tr, br, bl].
fn pattern_fitness(b: &Bin, c: [Point; 4], dim: usize) -> i32 {
    let t = corner_transform(c, dim);
    let cell = |x: i32, y: i32, dark: bool| -> i32 {
        let p = t.apply(x as f32 + 0.5, y as f32 + 0.5);
        (b.get(p.x as i32, p.y as i32) == dark) as i32
    };
    let d = dim as i32;
    let mut score = 0;
    // finders with their light separator ring
    for (fx, fy) in [(3, 3), (d - 4, 3), (3, d - 4)] {
        for dy in -4..=4i32 {
            for dx in -4..=4i32 {
                let r = dx.abs().max(dy.abs());
                let (x, y) = (fx + dx, fy + dy);
                if x < 0 || y < 0 || x >= d || y >= d {
                    continue;
                }
                score += cell(x, y, r != 2 && r != 4);
            }
        }
    }
    for k in 8..d - 8 {
        score += cell(k, 6, k % 2 == 0);
        score += cell(6, k, k % 2 == 0);
    }
    let mut pos = [0usize; 7];
    let n = crate::qr::alignment_positions(((dim - 17) / 4) as u8, &mut pos);
    for i in 0..n {
        for j in 0..n {
            if (i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0) {
                continue;
            }
            for dy in -2..=2i32 {
                for dx in -2..=2i32 {
                    let dark = dx.abs().max(dy.abs()) != 1;
                    score += 2 * cell(pos[i] as i32 + dx, pos[j] as i32 + dy, dark);
                }
            }
        }
    }
    score
}

/// Hill-climb the corners listed in `free` (indices into [tl, tr, br,
/// bl]) to maximise pattern fitness.
fn refine(
    b: &Bin,
    mut c: [Point; 4],
    free: &[usize],
    dim: usize,
    module: f32,
    start_step: f32,
) -> [Point; 4] {
    let mut best_score = pattern_fitness(b, c, dim);
    let mut step = module * start_step;
    let mut iters = 0;
    while step >= 0.25 && iters < 80 {
        iters += 1;
        let mut moved = false;
        for &k in free {
            for (dx, dy) in [(1.0, 0.0), (-1.0, 0.0), (0.0, 1.0), (0.0, -1.0)] {
                let mut trial = c;
                trial[k].x += dx * step;
                trial[k].y += dy * step;
                let sc = pattern_fitness(b, trial, dim);
                if sc > best_score {
                    best_score = sc;
                    c = trial;
                    moved = true;
                }
            }
        }
        if !moved {
            step /= 2.0;
        }
    }
    c
}

/// Best match of the 5x5 bottom-right alignment pattern within 3 modules
/// of its predicted place (module centre dim - 6.5) under `t`. Returns
/// its centre in image coordinates.
fn match_alignment(b: &Bin, t: &Transform, dim: usize) -> Option<Point> {
    let c = dim as f32 - 6.5;
    let mut best: Option<(i32, f32, f32, f32)> = None;
    for sv in -12..=12i32 {
        for su in -12..=12i32 {
            let (du, dv) = (su as f32 * 0.25, sv as f32 * 0.25);
            let mut score = 0;
            for j in -2..=2i32 {
                for i in -2..=2i32 {
                    let want_dark = i.abs().max(j.abs()) != 1;
                    let p = t.apply(c + du + i as f32, c + dv + j as f32);
                    if b.get(p.x as i32, p.y as i32) == want_dark {
                        score += 1;
                    }
                }
            }
            let off = abs(du) + abs(dv);
            let better = match best {
                None => true,
                Some((bs, _, _, boff)) => score > bs || (score == bs && off < boff),
            };
            if better {
                best = Some((score, du, dv, off));
            }
        }
    }
    let (score, du, dv, _) = best?;
    (score >= 24).then(|| t.apply(c + du, c + dv))
}

fn align_cross(c: &[i32; 3], module: f32) -> bool {
    let v = module / 2.0;
    c.iter().all(|&x| abs(module - x as f32) < v)
}

fn alignment_in_region(b: &Bin, sx: i32, sy: i32, width: i32, height: i32, module: f32) -> Option<Point> {
    let max_j = sx + width;
    let middle = sy + height / 2;
    let mut seen: [(f32, f32, f32); 8] = [(0.0, 0.0, 0.0); 8];
    let mut n_seen = 0usize;
    let handle = |c: &[i32; 3],
                  i: i32,
                  j: i32,
                  seen: &mut [(f32, f32, f32); 8],
                  n_seen: &mut usize|
     -> Option<Point> {
        let total: i32 = c.iter().sum();
        let cj = (j - c[2]) as f32 - c[1] as f32 / 2.0;
        let ci = align_cross_vertical(b, i, cj as i32, 2 * c[1], total, module)?;
        let est = total as f32 / 3.0;
        for s in seen.iter_mut().take(*n_seen) {
            if abs(ci - s.1) <= est && abs(cj - s.0) <= est {
                let diff = abs(est - s.2);
                if diff <= 1.0 || diff <= s.2 {
                    return Some(Point {
                        x: (s.0 + cj) / 2.0,
                        y: (s.1 + ci) / 2.0,
                    });
                }
            }
        }
        if *n_seen < seen.len() {
            seen[*n_seen] = (cj, ci, est);
            *n_seen += 1;
        }
        None
    };
    for gen in 0..height {
        let i = middle
            + if gen & 1 == 0 {
                (gen + 1) / 2
            } else {
                -((gen + 1) / 2)
            };
        let mut c = [0i32; 3];
        let mut j = sx;
        while j < max_j && !b.get(j, i) {
            j += 1;
        }
        let mut state = 0usize;
        while j < max_j {
            if b.get(j, i) {
                if state == 1 {
                    c[1] += 1;
                } else if state == 2 {
                    if align_cross(&c, module) {
                        if let Some(p) = handle(&c, i, j, &mut seen, &mut n_seen) {
                            return Some(p);
                        }
                    }
                    c = [c[2], 1, 0];
                    state = 1;
                } else {
                    state += 1;
                    c[state] += 1;
                }
            } else {
                if state == 1 {
                    state += 1;
                }
                c[state] += 1;
            }
            j += 1;
        }
        if align_cross(&c, module) {
            if let Some(p) = handle(&c, i, max_j, &mut seen, &mut n_seen) {
                return Some(p);
            }
        }
    }
    // nothing confirmed twice: take the first guess if there was one
    (n_seen > 0).then(|| Point {
        x: seen[0].0,
        y: seen[0].1,
    })
}

fn align_cross_vertical(
    b: &Bin,
    start_i: i32,
    cj: i32,
    max_count: i32,
    orig_total: i32,
    module: f32,
) -> Option<f32> {
    let h = b.h();
    let mut c = [0i32; 3];
    let mut i = start_i;
    while i >= 0 && b.get(cj, i) && c[1] <= max_count {
        c[1] += 1;
        i -= 1;
    }
    if i < 0 || c[1] > max_count {
        return None;
    }
    while i >= 0 && !b.get(cj, i) && c[0] <= max_count {
        c[0] += 1;
        i -= 1;
    }
    if c[0] > max_count {
        return None;
    }
    i = start_i + 1;
    while i < h && b.get(cj, i) && c[1] <= max_count {
        c[1] += 1;
        i += 1;
    }
    if i == h || c[1] > max_count {
        return None;
    }
    while i < h && !b.get(cj, i) && c[2] <= max_count {
        c[2] += 1;
        i += 1;
    }
    if c[2] > max_count {
        return None;
    }
    let total: i32 = c.iter().sum();
    if 5 * (total - orig_total).abs() >= 2 * orig_total {
        return None;
    }
    align_cross(&c, module).then(|| (i - c[2]) as f32 - c[1] as f32 / 2.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqrt_is_accurate() {
        for v in [0.25f32, 1.0, 2.0, 49.0, 1234.5, 1.0e6] {
            let r = sqrt(v);
            assert!(abs(r * r - v) / v < 1e-5, "{v} {r}");
        }
        assert_eq!(round(2.5), 3);
        assert_eq!(round(-2.5), -3);
    }

    #[test]
    fn transform_maps_corners() {
        let to = [
            Point { x: 10.0, y: 20.0 },
            Point { x: 110.0, y: 25.0 },
            Point { x: 120.0, y: 130.0 },
            Point { x: 5.0, y: 115.0 },
        ];
        let from = [
            Point { x: 0.0, y: 0.0 },
            Point { x: 21.0, y: 0.0 },
            Point { x: 21.0, y: 21.0 },
            Point { x: 0.0, y: 21.0 },
        ];
        let t = Transform::quad_to_quad(from, to);
        for k in 0..4 {
            let p = t.apply(from[k].x, from[k].y);
            assert!(dist(p, to[k]) < 1e-3, "{k}: {p:?}");
        }
    }
}
