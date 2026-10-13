(ns ^:no-doc dk.simongray.whatwg-mime.impl.bytes
  "The bytes of a resource on each platform: a byte array on the JVM and a
  Uint8Array in JavaScript, read as numbers from 0 to 255.")

;; MIME Sniffing, section 5.2
(def max-header-length
  "The most bytes of a resource that sniffing reads."
  1445)

(defn length
  "The number of bytes in `b`, or 0 for nil."
  ^long [b]
  (if (nil? b)
    0
    #?(:clj  (alength ^bytes b)
       :cljs (.-length b))))

(defn header-length
  "The number of bytes in `b` that sniffing reads: at most 1445."
  ^long [b]
  (min (length b) max-header-length))

(defn byte-at
  "The byte at `i` of the bytes `b`."
  ^long [b ^long i]
  #?(:clj  (bit-and (long (aget ^bytes b (unchecked-int i))) 0xFF)
     :cljs (aget b i)))

(defn- code-at
  "The code unit at `i` of the text `s`."
  ^long [s ^long i]
  #?(:clj  (long (int (.charAt ^String s (unchecked-int i))))
     :cljs (.charCodeAt s i)))

;; MIME Sniffing, section 3. No <= of three arguments here, since it boxes
;; them, which made the scan ten times slower.
(defn binary-data-byte?
  "Whether the byte `x` is a binary data byte: a control other than tab,
  LF, FF, CR and ESC."
  [^long x]
  (and (< x 0x20)
       (not (or (== x 0x09) (== x 0x0A) (== x 0x0C) (== x 0x0D) (== x 0x1B)))))

;; MIME Sniffing, section 3
(defn whitespace-byte?
  "Whether the byte `x` is a whitespace byte: tab, LF, FF, CR or space."
  [^long x]
  (or (== x 0x20) (== x 0x09) (== x 0x0A) (== x 0x0C) (== x 0x0D)))

;; MIME Sniffing, section 3
(defn tag-terminating-byte?
  "Whether the byte `x` is a tag-terminating byte: a space or >."
  [^long x]
  (or (== x 0x20) (== x 0x3E)))

(defn binary?
  "Whether the first `n` bytes of `b` hold a binary data byte."
  [b ^long n]
  (loop [i 0]
    (cond
      (== i n)                          false
      (binary-data-byte? (byte-at b i)) true
      :else                             (recur (inc i)))))

(defn bytes-at?
  "Whether the bytes `xs` come at `i` in the first `n` bytes of `b`."
  [b ^long n ^long i xs]
  (and (<= (+ i (count xs)) n)
       (every? true? (map-indexed #(== (byte-at b (+ i %1)) ^long %2) xs))))

(defn ascii-at?
  "Whether the ASCII text `s` comes at `i` in the first `n` bytes of `b`."
  [b ^long n ^long i s]
  (let [k (count s)]
    (and (<= (+ i k) n)
         (loop [j 0]
           (cond
             (== j k)                               true
             (== (byte-at b (+ i j)) (code-at s j)) (recur (inc j))
             :else                                  false)))))
