(ns ^:no-doc dk.simongray.whatwg-mime.impl.media
  "The signatures of MP4, WebM and MP3 without ID3 (MIME Sniffing, sections
  6.2.1 to 6.2.3), each checked in the first `n` bytes of `b`.

  As the standard writes them, its steps for WebM and MP3 reject WPT's own
  media files. These follow what the steps evidently mean, and cite the
  standard's issue beside each departure."
  (:require [dk.simongray.whatwg-mime.impl.bytes :as bytes]))

(defn- u32
  "The 32-bit unsigned big-endian number at `i` of the bytes `b`."
  ^long [b ^long i]
  ;; by multiplication, since a shift in JavaScript returns a signed number
  (+ (* 16777216 (bytes/byte-at b i))
     (* 65536 (bytes/byte-at b (+ i 1)))
     (* 256 (bytes/byte-at b (+ i 2)))
     (bytes/byte-at b (+ i 3))))

(defn- brand?
  "Whether an MP4 brand such as mp41 or mp42 is at `i` in the first `n`
  bytes of `b`."
  [b ^long n ^long i]
  (bytes/ascii-at? b n i "mp4"))

;; MIME Sniffing, section 6.2.1
(defn mp4?
  "Whether the first `n` bytes of `b` start with an MP4 ftyp box."
  [b ^long n]
  (and (>= n 12)
       (let [box-size (u32 b 0)]
         (and (<= box-size n)
              (zero? (rem box-size 4))
              (bytes/ascii-at? b n 4 "ftyp")
              (or (brand? b n 8)
                  ;; the compatible brands, after the major brand and its
                  ;; version
                  (boolean (some #(brand? b n %) (range 16 box-size 4))))))))

;; MIME Sniffing, section 6.2.2, "parse a vint", of which WebM needs only the
;; size. The standard reads the byte at 0 rather than at iter
;; (whatwg/mimesniff#146 and #167).
(defn- vint-size
  "The size in bytes of the variable-size integer at `i` in the first `n`
  bytes of `b`: one more than the leading zero bits of its first byte, at
  most eight."
  ^long [b ^long n ^long i]
  (let [x (bytes/byte-at b i)]
    (loop [size 1
           mask 0x80]
      (if (and (< size 8) (< size n) (zero? (bit-and x mask)))
        (recur (inc size) (bit-shift-right mask 1))
        size))))

;; MIME Sniffing, section 6.2.2, "matching a padded sequence", whose end WebM
;; never passes (whatwg/mimesniff#93 and #126)
(defn- padded-webm?
  "Whether webm comes at `i` in the first `n` bytes of `b`, after any zero
  bytes."
  [b ^long n ^long i]
  (let [start (loop [i i]
                (if (and (< i n) (zero? (bytes/byte-at b i)))
                  (recur (inc i))
                  i))]
    (bytes/ascii-at? b n start "webm")))

(defn- doctype-data
  "The index where the data of an EBML DocType element starts, given its
  ID 42 82 at `i` in the first `n` bytes of `b`, or nil when the bytes end
  first."
  [b ^long n ^long i]
  (let [i (+ i 2)]
    (when (< i n)
      (+ i (vint-size b n i)))))

;; MIME Sniffing, section 6.2.2
;; TODO: offer the fixes of vint-size and padded-webm? on whatwg/mimesniff#146,
;; and a pull request only if an editor asks for one.
(defn webm?
  "Whether the first `n` bytes of `b` start with an EBML header whose
  DocType, in its first 38 bytes, is webm."
  [b ^long n]
  (and (>= n 4)
       (bytes/bytes-at? b n 0 [0x1A 0x45 0xDF 0xA3])
       (loop [i 4]
         (cond
           (or (>= i n) (>= i 38))
           false

           (bytes/bytes-at? b n i [0x42 0x82])
           (let [data (doctype-data b n i)]
             (cond
               (or (nil? data) (>= data (- n 4))) false
               (padded-webm? b n data)            true
               :else                              (recur (inc (long data)))))

           :else
           (recur (inc i))))))

;; MIME Sniffing, section 6.2.3, the tables mp3-rates, mp2.5-rates and
;; sample-rate
(def mpeg-1-bit-rates
  "The bit rates of MPEG-1 audio layer III, by index."
  [0 32000 40000 48000 56000 64000 80000 96000 112000 128000 160000 192000
   224000 256000 320000])

(def mpeg-2-bit-rates
  "The bit rates of MPEG-2 and MPEG-2.5 audio layer III, by index."
  [0 8000 16000 24000 32000 40000 48000 56000 64000 80000 96000 112000
   128000 144000 160000])

(def sample-rates
  "The sample rates of MPEG-1 audio, by index, which MPEG-2 halves and
  MPEG-2.5 quarters."
  [44100 48000 32000])

(defn- bits
  "The bits of the byte `x` under the `mask`, shifted right by `shift`."
  ^long [^long x ^long mask ^long shift]
  (bit-shift-right (bit-and x mask) shift))

;; MIME Sniffing, section 6.2.3, "match an mp3 header". The standard checks
;; for 4 bytes only at the start of the file. It joins the two checks of the
;; sync bits with "and" where it means "or", and leaves the precedence of &
;; and >> open (whatwg/mimesniff#70 and #168).
(defn- mp3-header?
  "Whether the header of an MPEG audio layer III frame is at `s` in the
  first `n` bytes of `b`."
  [b ^long n ^long s]
  (and (<= (+ s 4) n)
       (== 0xFF (bytes/byte-at b s))
       (== 0xE0 (bits (bytes/byte-at b (+ s 1)) 0xE0 0))
       ;; the layer is 1 for layer III, as 4 - layer is 3
       (== 1 (bits (bytes/byte-at b (+ s 1)) 0x06 1))
       (not= 15 (bits (bytes/byte-at b (+ s 2)) 0xF0 4))
       (not= 3 (bits (bytes/byte-at b (+ s 2)) 0x0C 2))))

;; MIME Sniffing, section 6.2.3, "parse an mp3 frame" and "compute an mp3
;; frame size". The standard swaps the bit rates of MPEG-1 and MPEG-2.5, and
;; gives the scale of 72 to the reserved version 1 rather than to MPEG-2 and
;; 2.5 (ISO/IEC 11172-3 and 13818-3).
(defn- frame-size
  "The size in bytes of the MPEG audio layer III frame whose header is at
  `s` in the bytes `b`."
  ^long [b ^long s]
  (let [x           (bytes/byte-at b (+ s 1))
        y           (bytes/byte-at b (+ s 2))
        version     (bits x 0x18 3)
        mpeg-1?     (== 3 version)
        bit-rate    (nth (if mpeg-1? mpeg-1-bit-rates mpeg-2-bit-rates) (bits y 0xF0 4))
        sample-rate (quot (nth sample-rates (bits y 0x0C 2))
                          (case version 2 2 0 4 1))]
    (+ (quot (* bit-rate (if mpeg-1? 144 72)) sample-rate)
       (bits y 0x02 1))))

;; MIME Sniffing, section 6.2.3. The standard compares the frame size with
;; s - length rather than length - s, which no frame passes.
;; TODO: offer the fixes of mp3-header?, frame-size and mp3? on
;; whatwg/mimesniff#168, and a pull request only if an editor asks for one.
(defn mp3?
  "Whether the first `n` bytes of `b` start with two frames of MPEG audio
  layer III."
  [b ^long n]
  (and (mp3-header? b n 0)
       (let [size (frame-size b 0)]
         (and (<= 4 size n)
              (mp3-header? b n size)))))
