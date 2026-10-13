(ns dk.simongray.whatwg-mime.generative-test
  "Properties that hold for any input, tried on random text made of the
  code points that trip up a parser, and on random bytes that start like
  the resources that sniffing looks for.

  The standard promises that a parsed MIME type serializes to a valid
  string that parses back to the same type. It also promises that a
  resource served as plain text never sniffs as a type that runs scripts."
  (:require #?(:cljs ["util" :as util])
            [clojure.string :as str]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [dk.simongray.whatwg-mime :as mime]
            [dk.simongray.whatwg-mime.octets :refer [octets]]
            [dk.simongray.whatwg-mime.patterns :as patterns]))

(def code-unit
  "A code unit of the kinds that MIME types hold, the plain ones most
  often."
  (gen/frequency
   [[8 (gen/elements (map str "abcxyzABCXYZ019!#$%&'*+-.^_`|~"))]
    [6 (gen/elements ["/" ";" "=" "\"" "\\" "," " " "\t"])]
    [2 (gen/elements ["\n" "\r" "\f" "\u0000" "\u000B" "\u007F"])]
    [2 (gen/elements ["\u0080" "é" "ÿ" "Ā" "K" "ſ" "�"])]
    [1 (gen/return "\uD800")]]))

(def junk
  "Text of random code units."
  (gen/fmap str/join (gen/vector code-unit 0 12)))

(def token
  "A token, in any case."
  (gen/fmap str/join (gen/vector (gen/elements (map str "abcXYZ09!#+-.^")) 1 5)))

(def value
  "The value of a parameter: a token, junk, or junk in quotes."
  (gen/one-of [token junk (gen/fmap #(str "\"" % "\"") junk)]))

(def mime-type
  "Text shaped like a MIME type, with tokens or junk for its parts."
  (gen/fmap (fn [[type subtype parameters]]
              (str/join (concat [type "/" subtype]
                                (for [[k v] parameters]
                                  (str ";" k "=" v)))))
            (gen/tuple (gen/one-of [token junk])
                       (gen/one-of [token junk])
                       (gen/vector (gen/tuple (gen/one-of [token junk]) value) 0 4))))

(def text
  "Text that's a MIME type, or nearly one, or junk."
  (gen/frequency [[3 mime-type] [1 junk]]))

(defspec round-trip 500
  (prop/for-all [s text]
    (let [m (mime/parse s)]
      (or (nil? m)
          (let [serialized (mime/serialize m)]
            (and (mime/valid? serialized)
                 (= m (mime/parse serialized))
                 (= serialized (mime/serialize (mime/parse serialized)))))))))

(defspec valid-parses 500
  (prop/for-all [s text]
    (or (not (mime/valid? s))
        (some? (mime/parse s)))))

(defspec extract-of-one-value 500
  (prop/for-all [s text]
    (let [m (mime/parse s)]
      (or (str/includes? s ",")
          (= "*/*" (mime/essence m))
          (= m (mime/extract [s]))))))

#?(:cljs
   (defn- node-serialize
     "The text `s` as Node's util.MIMEType serializes it, or nil when it
     doesn't parse."
     [s]
     (try
       (.toString (util/MIMEType. s))
       (catch :default _
         nil))))

;; Node 24.1.0 reads the next parameter right after a quoted value, where the
;; standard first skips to the next semicolon. Node's main branch follows the
;; standard since its parser was rewritten in October 2026.
#?(:cljs
   (def node-skips-after-quotes?
     "Whether this Node skips what follows a quoted value up to the next
     semicolon, as the standard says."
     (= "a/a;a=\"\"" (node-serialize "a/a;a=\"\"ab=\""))))

#?(:cljs
   (defspec as-node-parses 500
     (prop/for-all [s text]
       (or (not node-skips-after-quotes?)
           (= (mime/serialize s) (node-serialize s))))))

(def start
  "The start of a resource: a signature, markup, text or random bytes."
  (gen/one-of
   [(gen/elements (map octets
                       ["<!DOCTYPE html>" "<html " "  <p>" "<?xml" "%PDF-1.7"
                        "<!-- -->" "<rss>" "ï»¿<feed>" "GIF89a"
                        "\u0089PNG\r\n\u001A\n" "ID3" "OggS\u0000" "PK\u0003\u0004"
                        "þÿ" "Hello" "\u0000"]))
    (gen/fmap #(apply octets %) (gen/vector (gen/choose 0 255) 0 16))]))

(def resource
  "The bytes of a resource: a start and random bytes after it."
  (gen/fmap (fn [[a b]] (octets (seq a) b))
            (gen/tuple start (gen/vector (gen/choose 0 255) 0 32))))

(def content-type
  "The Content-Type of a resource, or nil."
  (gen/elements [nil "" "text/plain" "text/plain; charset=UTF-8" "text/html"
                 "image/svg+xml" "image/png" "audio/mpeg" "application/octet-stream"
                 "unknown/unknown" "*/*"]))

(defspec plain-text-never-scriptable 300
  (prop/for-all [b resource]
    (not (mime/scriptable? (mime/sniff b "text/plain")))))

(defspec xml-and-html-stay 300
  (prop/for-all [b  resource
                 ct (gen/elements ["text/html" "image/svg+xml" "application/rss+xml" "text/xml"])]
    (= (mime/parse ct) (mime/sniff b ct))))

(defspec only-the-resource-header 100
  (prop/for-all [b     resource
                 ct    content-type
                 tail  (gen/vector (gen/choose 0 255) 1 64)
                 fill  (gen/choose 0 255)]
    (let [n      patterns/resource-header-length
          header (octets (take n (concat (seq b) (repeat fill))))
          longer (octets (seq header) tail)]
      (and (= (mime/sniff header ct) (mime/sniff longer ct))
           (= (patterns/feed-type header) (patterns/feed-type longer))))))
