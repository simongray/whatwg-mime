(ns dk.simongray.whatwg-mime.patterns
  "The byte patterns of the MIME Sniffing Standard, and the functions that
  match them against the first bytes of a resource.

  The bytes are a byte array on the JVM and a Uint8Array in ClojureScript
  (a Node Buffer is one). Only the first 1445 count, so a whole body will
  do. Each function returns a MIME type as text, e.g. image/png, or nil
  when nothing matches.

  A row of a table is a map of:

  - :pattern, the bytes to match, with :tt for a space or > after a tag
  - :mask, how much of each byte counts: all of it for 0xFF, all but the
    case of a letter for 0xDF, and none of it for 0x00
  - :ignored, the bytes that may come before the pattern
  - :type, the MIME type of a match"
  (:require [clojure.string :as str]
            [dk.simongray.whatwg-mime.impl.bytes :as bytes]
            [dk.simongray.whatwg-mime.impl.feed :as feed]
            [dk.simongray.whatwg-mime.impl.media :as media]))

;; MIME Sniffing, section 5.2
(def resource-header-length
  "The largest number of bytes that sniffing reads from a resource."
  bytes/max-header-length)

(defn- hex
  "The bytes of the text `s` in hexadecimal, e.g. 3C 21, with :tt for TT."
  [s]
  (mapv #(if (= "TT" %)
           :tt
           #?(:clj (Long/parseLong % 16) :cljs (js/parseInt % 16)))
        (str/split s #" ")))

(defn- row
  "A row of a table: the `pattern` and `mask` as the standard writes them,
  the bytes `ignored` before the pattern and the `type` of a match."
  [pattern mask ignored type]
  {:pattern (hex pattern) :mask (hex mask) :ignored ignored :type type})

;; MIME Sniffing, section 3
(def whitespace-bytes
  "The bytes that some patterns ignore before them: tab, LF, FF, CR and
  space."
  #{0x09 0x0A 0x0C 0x0D 0x20})

;; MIME Sniffing, section 6.1
(def image-patterns
  "The table of image patterns."
  [(row "00 00 01 00" "FF FF FF FF" #{} "image/x-icon")
   (row "00 00 02 00" "FF FF FF FF" #{} "image/x-icon")
   (row "42 4D" "FF FF" #{} "image/bmp")
   (row "47 49 46 38 37 61" "FF FF FF FF FF FF" #{} "image/gif")
   (row "47 49 46 38 39 61" "FF FF FF FF FF FF" #{} "image/gif")
   (row "52 49 46 46 00 00 00 00 57 45 42 50 56 50"
        "FF FF FF FF 00 00 00 00 FF FF FF FF FF FF" #{} "image/webp")
   (row "89 50 4E 47 0D 0A 1A 0A" "FF FF FF FF FF FF FF FF" #{} "image/png")
   (row "FF D8 FF" "FF FF FF" #{} "image/jpeg")])

;; MIME Sniffing, section 6.2
(def audio-or-video-patterns
  "The table of audio and video patterns. The checks for MP4, WebM and MP3
  without ID3 come after it."
  [(row "46 4F 52 4D 00 00 00 00 41 49 46 46"
        "FF FF FF FF 00 00 00 00 FF FF FF FF" #{} "audio/aiff")
   (row "49 44 33" "FF FF FF" #{} "audio/mpeg")
   (row "4F 67 67 53 00" "FF FF FF FF FF" #{} "application/ogg")
   (row "4D 54 68 64 00 00 00 06" "FF FF FF FF FF FF FF FF" #{} "audio/midi")
   (row "52 49 46 46 00 00 00 00 41 56 49 20"
        "FF FF FF FF 00 00 00 00 FF FF FF FF" #{} "video/avi")
   (row "52 49 46 46 00 00 00 00 57 41 56 45"
        "FF FF FF FF 00 00 00 00 FF FF FF FF" #{} "audio/wave")])

;; MIME Sniffing, section 6.3
(def font-patterns
  "The table of font patterns."
  [;; 34 bytes, then LP
   (row (str (str/join " " (repeat 34 "00")) " 4C 50")
        (str (str/join " " (repeat 34 "00")) " FF FF")
        #{} "application/vnd.ms-fontobject")
   (row "00 01 00 00" "FF FF FF FF" #{} "font/ttf")
   (row "4F 54 54 4F" "FF FF FF FF" #{} "font/otf")
   (row "74 74 63 66" "FF FF FF FF" #{} "font/collection")
   (row "77 4F 46 46" "FF FF FF FF" #{} "font/woff")
   (row "77 4F 46 32" "FF FF FF FF" #{} "font/woff2")])

;; MIME Sniffing, section 6.4
(def archive-patterns
  "The table of archive patterns."
  [(row "1F 8B 08" "FF FF FF" #{} "application/x-gzip")
   (row "50 4B 03 04" "FF FF FF FF" #{} "application/zip")
   (row "52 61 72 21 1A 07 00" "FF FF FF FF FF FF FF" #{} "application/x-rar-compressed")])

;; MIME Sniffing, section 7.1, step 1
(def scriptable-patterns
  "The table of HTML, XML and PDF patterns, which unknown-type tries only
  when asked to."
  [(row "3C 21 44 4F 43 54 59 50 45 20 48 54 4D 4C TT"
        "FF FF DF DF DF DF DF DF DF FF DF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 48 54 4D 4C TT" "FF DF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 48 45 41 44 TT" "FF DF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 53 43 52 49 50 54 TT" "FF DF DF DF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 49 46 52 41 4D 45 TT" "FF DF DF DF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 48 31 TT" "FF DF FF FF" whitespace-bytes "text/html")
   (row "3C 44 49 56 TT" "FF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 46 4F 4E 54 TT" "FF DF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 54 41 42 4C 45 TT" "FF DF DF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 41 TT" "FF DF FF" whitespace-bytes "text/html")
   (row "3C 53 54 59 4C 45 TT" "FF DF DF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 54 49 54 4C 45 TT" "FF DF DF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 42 TT" "FF DF FF" whitespace-bytes "text/html")
   (row "3C 42 4F 44 59 TT" "FF DF DF DF DF FF" whitespace-bytes "text/html")
   (row "3C 42 52 TT" "FF DF DF FF" whitespace-bytes "text/html")
   (row "3C 50 TT" "FF DF FF" whitespace-bytes "text/html")
   (row "3C 21 2D 2D TT" "FF FF FF FF FF" whitespace-bytes "text/html")
   (row "3C 3F 78 6D 6C" "FF FF FF FF FF" whitespace-bytes "text/xml")
   (row "25 50 44 46 2D" "FF FF FF FF FF" #{} "application/pdf")])

;; MIME Sniffing, section 7.1, step 2
(def unknown-patterns
  "The table of PostScript and of text with a byte order mark, which
  unknown-type always tries."
  [(row "25 21 50 53 2D 41 64 6F 62 65 2D"
        "FF FF FF FF FF FF FF FF FF FF FF" #{} "application/postscript")
   (row "FE FF 00 00" "FF FF 00 00" #{} "text/plain")
   (row "FF FE 00 00" "FF FF 00 00" #{} "text/plain")
   (row "EF BB BF 00" "FF FF FF 00" #{} "text/plain")])

(defn- skip-ignored
  "The index of the first byte of `b` that isn't in the set `ignored`, or
  `n` when there's none before it."
  ^long [b ^long n ignored]
  (loop [i 0]
    (if (and (< i n) (contains? ignored (bytes/byte-at b i)))
      (recur (inc i))
      i)))

(defn- byte-matches?
  "Whether the byte `x` matches the byte `p` of a pattern under the byte
  `m` of its mask."
  [^long x p ^long m]
  (if (= :tt p)
    (bytes/tag-terminating-byte? x)
    (== (bit-and x m) (long p))))

;; MIME Sniffing, section 6
(defn matches?
  "Whether the bytes `b` match the `pattern` under the `mask`, after any
  leading bytes in the set `ignored`."
  [b pattern mask ignored]
  (let [n     (bytes/header-length b)
        k     (count pattern)
        start (skip-ignored b n ignored)]
    ;; the standard doesn't check that enough bytes are left after those
    ;; it ignores
    (and (<= (+ start k) n)
         (loop [j 0]
           (cond
             (== j k)
             true

             (byte-matches? (bytes/byte-at b (+ start j)) (nth pattern j) (nth mask j))
             (recur (inc j))

             :else
             false)))))

(defn- table-type
  "The type of the first row of the `table` whose pattern the bytes `b`
  match, or nil."
  [table b]
  (some (fn [{:keys [pattern mask ignored type]}]
          (when (matches? b pattern mask ignored)
            type))
        table))

;; MIME Sniffing, section 6.1
(defn image-type
  "The image type that the bytes `b` match, or nil."
  [b]
  (table-type image-patterns b))

;; MIME Sniffing, section 6.2
(defn audio-or-video-type
  "The audio or video type that the bytes `b` match, or nil."
  [b]
  (let [n (bytes/header-length b)]
    (or (table-type audio-or-video-patterns b)
        (when (media/mp4? b n) "video/mp4")
        (when (media/webm? b n) "video/webm")
        (when (media/mp3? b n) "audio/mpeg"))))

;; MIME Sniffing, section 6.3
(defn font-type
  "The font type that the bytes `b` match, or nil."
  [b]
  (table-type font-patterns b))

;; MIME Sniffing, section 6.4
(defn archive-type
  "The archive type that the bytes `b` match, or nil."
  [b]
  (table-type archive-patterns b))

;; MIME Sniffing, section 7.1
(defn unknown-type
  "The MIME type of a resource whose type is unknown, by its first bytes
  `b`. HTML, XML and PDF are among the candidates only when `scriptable?`.

  When no table matches, it's text/plain, or application/octet-stream when
  the bytes hold a control other than tab, LF, FF, CR or ESC."
  ([b]
   (unknown-type b false))
  ([b scriptable?]
   (or (when scriptable?
         (table-type scriptable-patterns b))
       (table-type unknown-patterns b)
       (image-type b)
       (audio-or-video-type b)
       (archive-type b)
       (if (bytes/binary? b (bytes/header-length b))
         "application/octet-stream"
         "text/plain"))))

;; MIME Sniffing, section 7.2
(defn text-or-binary
  "The type of a resource served as plain text, by its first bytes `b`:
  text/plain, or application/octet-stream when they hold a binary control
  and no byte order mark."
  [b]
  (let [n (bytes/header-length b)]
    (if (or (bytes/bytes-at? b n 0 [0xFE 0xFF])
            (bytes/bytes-at? b n 0 [0xFF 0xFE])
            (bytes/bytes-at? b n 0 [0xEF 0xBB 0xBF])
            (not (bytes/binary? b n)))
      "text/plain"
      "application/octet-stream")))

;; MIME Sniffing until 15 July 2024, section 7.3
(defn feed-type
  "The feed type that the bytes `b` start with, application/rss+xml or
  application/atom+xml, or nil.

  The standard had these rules for a feed served as HTML until 15 July
  2024, when it dropped them because no browser follows them. A feed starts
  with the root element of RSS, Atom or RSS 1.0, after any comments,
  declarations and processing instructions."
  [b]
  (feed/feed-type b (bytes/header-length b)))
