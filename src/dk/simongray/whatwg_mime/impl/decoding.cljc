(ns ^:no-doc dk.simongray.whatwg-mime.impl.decoding
  "Decoding bytes as text in an encoding of the Encoding Standard. This is
  no part of the MIME Sniffing Standard, but a convenience for the text
  that a charset names.

  It follows the Encoding Standard's decode (section 6), where a byte
  order mark overrides the encoding, and decodes windows-1252 and
  replacement itself. Every other encoding goes to the platform's decoder,
  java.nio.charset on the JVM and TextDecoder in JavaScript, which can
  differ from the standard's in a few corners."
  (:require [dk.simongray.whatwg-mime.impl.bytes :as bytes]))

;; Encoding Standard, section 6, "BOM sniff"
(defn bom
  "The encoding that the byte order mark of the bytes `b` names and the
  length of the mark, as a pair, or nil."
  [b]
  (let [n (bytes/length b)]
    (cond
      (bytes/bytes-at? b n 0 [0xEF 0xBB 0xBF]) ["UTF-8" 3]
      (bytes/bytes-at? b n 0 [0xFE 0xFF])      ["UTF-16BE" 2]
      (bytes/bytes-at? b n 0 [0xFF 0xFE])      ["UTF-16LE" 2])))

;; Encoding Standard, index-windows-1252.txt, where every other byte is its
;; own code point
(def windows-1252-c1
  "The code points of the bytes 0x80 to 0x9F in windows-1252."
  [0x20AC 0x0081 0x201A 0x0192 0x201E 0x2026 0x2020 0x2021
   0x02C6 0x2030 0x0160 0x2039 0x0152 0x008D 0x017D 0x008F
   0x0090 0x2018 0x2019 0x201C 0x201D 0x2022 0x2013 0x2014
   0x02DC 0x2122 0x0161 0x203A 0x0153 0x009D 0x017E 0x0178])

(defn- windows-1252-code
  "The code point of the byte `x` in windows-1252."
  ^long [^long x]
  (if (and (<= 0x80 x) (<= x 0x9F))
    (long (nth windows-1252-c1 (- x 0x80)))
    x))

#?(:cljs
   (defn- with-windows-1252-c1
     "The text `s` with each C1 control as the character of its byte in
     windows-1252."
     [s]
     (.replace s (js/RegExp. "[\u0080-\u009F]" "g")
               #(.fromCharCode js/String (windows-1252-code (.charCodeAt % 0))))))

;; Encoding Standard, section 9.1, the single-byte decoder. The platforms'
;; own decoders differ: Java's gives U+FFFD for five of the bytes 0x80 to
;; 0x9F, and Node's gives the C1 controls for all of them. In JavaScript,
;; TextDecoder with the C1 controls replaced is ten times faster than a
;; string built by the byte, and a browser's has no C1 controls to replace
;; but those that the index keeps.
(defn- windows-1252
  "The text of the bytes `b` from `start` to `end` in windows-1252."
  [b ^long start ^long end]
  #?(:clj  (let [n  (- end start)
                 cs (char-array n)]
             (dotimes [i n]
               (aset cs i (char (windows-1252-code (bytes/byte-at b (+ start i))))))
             (String. cs))
     :cljs (with-windows-1252-c1
             (.decode (js/TextDecoder. "windows-1252" #js {:ignoreBOM true})
                      (.subarray b start end)))))

;; the names of the Encoding Standard that Java spells another way, where
;; GBK's decoder is gb18030's (section 10.1.1)
#?(:clj
   (def java-charsets
     "The Java charset of each encoding that Java knows by another name."
     {"GBK"            "GB18030"
      "ISO-8859-8-I"   "ISO-8859-8"
      "macintosh"      "x-MacRoman"
      "x-mac-cyrillic" "x-MacCyrillic"}))

(defn- platform
  "The text of the bytes `b` from `start` to `end` in `encoding`, by the
  platform's decoder, or in UTF-8 when the platform lacks one."
  [b ^long start ^long end encoding]
  #?(:clj  (let [^java.nio.charset.Charset charset
                 (try
                   (java.nio.charset.Charset/forName (get java-charsets encoding encoding))
                   (catch Exception _
                     java.nio.charset.StandardCharsets/UTF_8))]
             (String. ^bytes b (int start) (int (- end start)) charset))
     ;; with ignoreBOM, as the byte order mark has gone already and a second
     ;; one stays, as it does on the JVM
     :cljs (let [decoder (try
                           (js/TextDecoder. encoding #js {:ignoreBOM true})
                           (catch :default _
                             (js/TextDecoder. "utf-8" #js {:ignoreBOM true})))]
             (.decode decoder (.subarray b start end)))))

;; Encoding Standard, section 6, "decode"
(defn decode
  "The text of the bytes `b` in `encoding`, or in UTF-8 when it's nil,
  unless a byte order mark names another. The mark goes."
  [b encoding]
  (let [[bom-encoding bom-length] (bom b)
        encoding                  (or bom-encoding encoding "UTF-8")
        start                     (or bom-length 0)
        end                       (bytes/length b)]
    (cond
      (nil? b)
      ""

      (= "windows-1252" encoding)
      (windows-1252 b start end)

      ;; section 14.1.1: a single U+FFFD for any bytes at all
      (= "replacement" encoding)
      (if (< start end) "�" "")

      :else
      (platform b start end encoding))))
