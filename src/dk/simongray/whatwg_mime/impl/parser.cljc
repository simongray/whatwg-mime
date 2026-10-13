(ns ^:no-doc dk.simongray.whatwg-mime.impl.parser
  "Parsing and serializing MIME types (MIME Sniffing, sections 4.3 to 4.5),
  and splitting the values of a header (Fetch, section 2.2).

  The parser steps through UTF-16 code units rather than code points.
  That's safe, since every character that it looks for is in Latin-1 and
  so can't be half of a surrogate pair."
  (:require [clojure.string :as str]))

(defn- length
  "The number of code units of the text `s`."
  ^long [s]
  #?(:clj  (.length ^String s)
     :cljs (.-length s)))

(defn- code-at
  "The code unit at `i` of the text `s`."
  ^long [s ^long i]
  #?(:clj  (long (int (.charAt ^String s (unchecked-int i))))
     :cljs (.charCodeAt s i)))

;; tokens are ASCII, so this is the ASCII lower case of Infra for them
(defn- lower-case
  "The token `s` in lower case, whatever the locale."
  [s]
  #?(:clj  (.toLowerCase ^String s java.util.Locale/ROOT)
     :cljs (.toLowerCase s)))

;; Fetch Standard, section 2.2
(defn- http-whitespace?
  "Whether the code unit `c` is HTTP whitespace: LF, CR, tab or space."
  [^long c]
  (or (== c 0x20) (== c 0x09) (== c 0x0A) (== c 0x0D)))

;; Fetch Standard, section 2.2
(defn- http-tab-or-space?
  "Whether the code unit `c` is a tab or a space."
  [^long c]
  (or (== c 0x20) (== c 0x09)))

(defn- between?
  "Whether the code unit `c` is from `lo` to `hi`."
  [^long lo ^long c ^long hi]
  ;; <= boxes its arguments when there are three
  (and (<= lo c) (<= c hi)))

;; MIME Sniffing, section 3
(defn- token-code-point?
  "Whether the code unit `c` is an HTTP token code point."
  [^long c]
  (or (between? 0x61 c 0x7A)
      (between? 0x41 c 0x5A)
      (between? 0x30 c 0x39)
      (case c
        (0x21 0x23 0x24 0x25 0x26 0x27 0x2A 0x2B 0x2D 0x2E 0x5E 0x5F 0x60 0x7C 0x7E) true
        false)))

;; MIME Sniffing, section 3
(defn- quoted-string-code-point?
  "Whether the code unit `c` is an HTTP quoted-string token code point."
  [^long c]
  (or (between? 0x20 c 0x7E) (== c 0x09) (between? 0x80 c 0xFF)))

(defn- every-code?
  "Whether each code unit of the text `s` passes `pred`."
  [pred s]
  (let [n (length s)]
    (loop [i 0]
      (cond
        (== i n)             true
        (pred (code-at s i)) (recur (inc i))
        :else                false))))

(defn token?
  "Whether the text `s` is a token: one or more HTTP token code points."
  [s]
  (and (pos? (length s)) (every-code? token-code-point? s)))

(defn- skip-while
  "The index of the first code unit of the text `s` from `i` that doesn't
  pass `pred`, or the end."
  ^long [s ^long i pred]
  (let [n (length s)]
    (loop [i i]
      (if (and (< i n) (pred (code-at s i)))
        (recur (inc i))
        i))))

(defn- skip-to
  "The index of the code unit `c` in the text `s` from `i`, or the end."
  ^long [s ^long i ^long c]
  (skip-while s i #(not (== c ^long %))))

(defn- skip-to-either
  "The index of the code unit `a` or `b` in the text `s` from `i`, or the
  end."
  ^long [s ^long i ^long a ^long b]
  (skip-while s i #(not (or (== a ^long %) (== b ^long %)))))

(defn- trim-end
  "The text `s` without the trailing code units that pass `pred`."
  [s pred]
  (loop [end (length s)]
    (if (and (pos? end) (pred (code-at s (dec end))))
      (recur (dec end))
      (subs s 0 end))))

(defn- trim
  "The text `s` without the leading and trailing code units that pass
  `pred`."
  [s pred]
  (trim-end (subs s (skip-while s 0 pred)) pred))

;; Infra
(defn- ascii-whitespace?
  "Whether the code unit `c` is ASCII whitespace: tab, LF, FF, CR or
  space."
  [^long c]
  (or (== c 0x20) (== c 0x09) (== c 0x0A) (== c 0x0C) (== c 0x0D)))

(defn strip-ascii-whitespace
  "The text `s` without its leading and trailing ASCII whitespace."
  [s]
  (trim s ascii-whitespace?))

;; Infra. The JVM and JavaScript lower other letters too, e.g. the Kelvin
;; sign to k.
(defn ascii-lower-case
  "The text `s` with its ASCII capital letters in lower case."
  [s]
  (str/replace s #"[A-Z]+" lower-case))

;; Fetch Standard, section 2.2, "collect an HTTP quoted string", where a
;; backslash escapes the code unit after it
(defn- quoted-value
  "The value inside the quoted string at `start` of the text `s`, and the
  index after it, as a pair."
  [s ^long start]
  (let [n (length s)]
    (loop [i     (inc start)
           value ""]
      (let [j     (skip-to-either s i 0x22 0x5C)
            value (str value (subs s i j))]
        (cond
          (== j n)                [value n]
          (== 0x22 (code-at s j)) [value (inc j)]
          (== (inc j) n)          [(str value "\\") n]
          :else                   (recur (+ j 2) (str value (subs s (inc j) (+ j 2)))))))))

(defn quoted-string
  "The quoted string at `start` of the text `s` and the index after it, as
  a pair: the value inside the quotes when `extract?`, or else the string
  as it's written."
  [s start extract?]
  (let [[_ end :as found] (quoted-value s start)]
    (if extract?
      found
      [(subs s start end) end])))

;; MIME Sniffing, section 4.4, step 11.8 and 11.9
(defn- parameter-value
  "The value of the parameter that starts at `i` of the text `s`, and the
  index of the semicolon after it (or the end), as a pair. The value is
  nil when it's empty and unquoted."
  [s ^long i]
  (if (== 0x22 (code-at s i))
    (let [[value end] (quoted-value s i)]
      ;; the rest up to the semicolon goes, e.g. iso-2022-jp in
      ;; charset="shift_jis"iso-2022-jp
      [value (skip-to s end 0x3B)])
    (let [end   (skip-to s i 0x3B)
          value (trim-end (subs s i end) http-whitespace?)]
      [(not-empty value) end])))

;; MIME Sniffing, section 4.4, step 11.10
(defn- add-parameter
  "The name-value `pairs` with `name` and `value` added, unless the name
  isn't a token, the value holds a code point that a quoted string can't,
  or the name is taken."
  [pairs name value]
  (if (and (token? name)
           (every-code? quoted-string-code-point? value))
    (let [name (lower-case name)]
      (cond-> pairs
        (not-any? #(= name (first %)) pairs) (conj [name value])))
    pairs))

;; MIME Sniffing, section 4.4, step 11
(defn- parameter-pairs
  "The parameters of the text `s` from the semicolon at `i`, as name-value
  pairs in the order of the text."
  [s ^long i]
  (let [n (length s)]
    (loop [i     i
           pairs []]
      (if (>= i n)
        pairs
        (let [start (skip-while s (inc i) http-whitespace?)
              end   (skip-to-either s start 0x3B 0x3D)
              name  (subs s start end)]
          (cond
            (== end n)                pairs
            (== 0x3B (code-at s end)) (recur end pairs)
            (== (inc end) n)          pairs
            :else
            (let [[value end] (parameter-value s (inc end))]
              (recur (long end) (cond-> pairs value (add-parameter name value))))))))))

;; an array map keeps its order at any size, until an assoc past eight
;; entries turns it into a hash map
(defn ordered-map
  "The name-value `pairs` as a map in their order."
  [pairs]
  (apply array-map (mapcat identity pairs)))

;; MIME Sniffing, section 4.4
(defn parse
  "The MIME type in the text `s`, or nil when it doesn't parse."
  [s]
  (let [s     (trim s http-whitespace?)
        n     (length s)
        slash (skip-to s 0 0x2F)
        type  (subs s 0 slash)]
    (when (and (token? type) (< slash n))
      (let [semicolon (skip-to s (inc slash) 0x3B)
            subtype   (trim-end (subs s (inc slash) semicolon) http-whitespace?)]
        (when (token? subtype)
          (let [pairs (parameter-pairs s semicolon)]
            (cond-> {:type (lower-case type) :subtype (lower-case subtype)}
              (seq pairs) (assoc :parameters (ordered-map pairs)))))))))

;; MIME Sniffing, section 4.5, step 2.4
(defn- quote-value
  "The parameter `value` as a token, or else as a quoted string."
  [value]
  (if (token? value)
    value
    (str "\"" (str/replace value #"[\"\\]" #(str "\\" %)) "\"")))

;; MIME Sniffing, section 4.5
(defn serialize
  "The text of the MIME type `m`."
  [{:keys [type subtype parameters] :as m}]
  (apply str type "/" subtype
         (for [[name value] parameters]
           (str ";" name "=" (quote-value value)))))

;; MIME Sniffing, section 4.3: HTTP's grammar of media types. The standard's
;; example rejects the empty parameter of text/html;, as RFC 7231 did,
;; though RFC 9110 allows it.
(def valid-pattern
  "The pattern of a valid MIME type string."
  (let [token  "[!#$%&'*+\\-.^_`|~0-9A-Za-z]+"
        quoted "\"(?:[\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\""]
    (re-pattern (str token "/" token
                     "(?:[\\t ]*;[\\t ]*" token "=(?:" token "|" quoted "))*"))))

(defn valid?
  "Whether the text `s` is a valid MIME type string."
  [s]
  (boolean (re-matches valid-pattern s)))

;; Fetch Standard, section 2.2.2, "get, decode, and split", the values
;; already decoded
(defn split-values
  "The values of a header in the text `s`, split at the commas outside
  quoted strings and trimmed of tabs and spaces."
  [s]
  (let [n (length s)]
    (loop [i      0
           value  ""
           values []]
      (let [j     (skip-to-either s i 0x22 0x2C)
            value (str value (subs s i j))]
        (if (and (< j n) (== 0x22 (code-at s j)))
          (let [[quoted end] (quoted-string s j false)
                value        (str value quoted)]
            (if (< (long end) n)
              (recur (long end) value values)
              (conj values (trim value http-tab-or-space?))))
          (let [values (conj values (trim value http-tab-or-space?))]
            (if (< j n)
              (recur (inc j) "" values)
              values)))))))
