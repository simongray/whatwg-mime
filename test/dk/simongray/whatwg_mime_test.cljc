(ns dk.simongray.whatwg-mime-test
  "The functions of the root namespace beyond what WPT's data checks, with
  the Content-Types that wary-fetch read wrongly."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dk.simongray.whatwg-mime :as mime]
            [dk.simongray.whatwg-mime.impl.labels :as labels]
            [dk.simongray.whatwg-mime.octets :refer [octets]]
            [dk.simongray.whatwg-mime.test-data :as test-data]))

(deftest parse
  (is (= {:type "text" :subtype "html" :parameters {"charset" "utf-8" "x" "("}}
         (mime/parse "Text/HTML; Charset=\"utf-8\"; x=(")))
  (is (= {:type "text" :subtype "html"} (mime/parse "text/html;")) "an empty parameter")
  (is (= {:type "a" :subtype "a" :parameters {"a" ""}} (mime/parse "a/a;a=\"\"ab=\""))
      "what follows a quoted value, up to the next semicolon, goes")
  (testing "text that isn't a MIME type"
    (doseq [s [nil "" "text" "text/" "/html" "text html" "text/ html" "text/plain, text/html"
               "\"text/html\""]]
      (is (nil? (mime/parse s)) (pr-str s))))
  (testing "the order of many parameters"
    (let [names (map #(str "p" %) (range 12))
          s     (apply str "a/b" (map #(str ";" % "=1") names))]
      (is (= names (keys (:parameters (mime/parse s)))))
      (is (= s (mime/serialize s))))))

(deftest serialize
  (is (= "text/html;charset=utf-8;x=\"(\"" (mime/serialize "Text/HTML; Charset=\"utf-8\"; x=(")))
  (is (= "a/b;x=\"\"" (mime/serialize "a/b;x=\"\"")) "an empty value")
  (is (= "a/b;x=\"a \\\"b\\\" \\\\c\"" (mime/serialize "a/b;x=\"a \\\"b\\\" \\\\c\"")) "escapes")
  (is (= "text/plain;b=2;a=\"x y\""
         (mime/serialize {:type "text" :subtype "plain" :parameters [["b" "2"] ["a" "x y"]]}))
      "parameters as pairs")
  (is (nil? (mime/serialize "text html"))))

(deftest charset
  (is (= "utf-8" (mime/charset "text/html; x=\"charset=evil\"; charset=utf-8"))
      "not the charset in another parameter, as wary-fetch read it")
  (is (= "UTF-8" (mime/charset {:type "text" :subtype "plain" :parameters [["charset" "UTF-8"]]})))
  (is (nil? (mime/charset "text/html"))))

(deftest encoding
  (is (= "windows-1252" (mime/encoding "text/html; charset=latin1")))
  (is (= "windows-1252" (mime/encoding "text/html; charset=\"  ISO-8859-1 \""))
      "whitespace and case")
  (is (= "UTF-8" (mime/encoding "text/html; charset=utf8")))
  (is (= "replacement" (mime/encoding "text/html; charset=iso-2022-kr")))
  (is (nil? (mime/encoding "text/html; charset=Koi8-r")) "the Kelvin sign isn't a k")
  (is (nil? (mime/encoding "text/html; charset=utf-7")))
  (is (nil? (mime/encoding "text/html")))
  (testing "a label on its own"
    (is (= "UTF-16LE" (mime/label->encoding "unicode")))
    (is (= "macintosh" (mime/label->encoding " X-Mac-Roman\n")))
    (is (nil? (mime/label->encoding nil)))))

(deftest labels
  (when-let [data (test-data/json "encoding/encodings.json")]
    (is (= (into {}
                 (for [group    data
                       encoding (get group "encodings")]
                   [(get encoding "name") (set (get encoding "labels"))]))
           (update-vals labels/encodings set))
        "the table of the Encoding Standard")))

(defn- text-of
  "The text of the code points `cps`, each in the Basic Multilingual Plane."
  [cps]
  (apply str (map #?(:clj #(char %) :cljs #(.fromCharCode js/String %)) cps)))

(defn- windows-1252-index
  "The code point of each pointer in the text `index`, the Encoding
  Standard's index-windows-1252.txt."
  [index]
  (into {}
        (for [line  (str/split-lines index)
              :when (re-find #"^\s*\d" line)
              :let  [[pointer code-point] (str/split (str/trim line) #"\s+")]]
          [(parse-long pointer)
           #?(:clj  (Long/parseLong (subs code-point 2) 16)
              :cljs (js/parseInt (subs code-point 2) 16))])))

(deftest decode
  (when-let [index (some-> (test-data/text "encoding/index-windows-1252.txt") windows-1252-index)]
    (is (= (text-of (for [x (range 256)] (if (< x 0x80) x (index (- x 0x80)))))
           (mime/decode (apply octets (range 256)) "latin1"))
        "windows-1252 by the index of the Encoding Standard, on every platform"))
  (testing "a byte order mark overrides the label and goes, but a second one stays"
    (is (= "hi" (mime/decode (octets [0xEF 0xBB 0xBF] "hi") "latin1")))
    (is (= "hi" (mime/decode (octets [0xFF 0xFE] "h" 0 "i" 0) "utf-8")))
    (is (= "hi" (mime/decode (octets [0xFE 0xFF] 0 "h" 0 "i") nil)))
    (is (= "﻿x" (mime/decode (octets [0xEF 0xBB 0xBF 0xEF 0xBB 0xBF] "x") nil))))
  (testing "UTF-8 for no label, or one of no encoding"
    (is (= "å" (mime/decode (octets [0xC3 0xA5]) nil)))
    (is (= "å" (mime/decode (octets [0xC3 0xA5]) "nonsense"))))
  (testing "an encoding that Java knows by another name"
    (is (= "Blåbær" (mime/decode (octets "Bl" 0x8C "b" 0xBE "r") "x-mac-roman"))))
  (testing "a label of the replacement encoding, as one U+FFFD"
    (is (= "�" (mime/decode (octets "<b>hi</b>") "iso-2022-kr")))
    (is (= "" (mime/decode (octets) "iso-2022-kr"))))
  (is (= "" (mime/decode nil "utf-8")) "no bytes"))

(deftest valid?
  (doseq [s ["text/html" "text/html; charset=utf-8" "text/html;charset=\"a \\\"b\\\"\""
             "a/b;x=\"ü\"" "a/b ;\tx=y"]]
    (is (mime/valid? s) (pr-str s)))
  (doseq [s [nil "" "text/html;" " text/html" "text/html; charset" "text/html; charset=" "a/b;x=ü"
             "text/html; charset=\"utf-8" "text/html,text/plain"]]
    (is (not (mime/valid? s)) (pr-str s))))

(deftest groups
  (is (mime/font? "application/font-otf") "as the standard corrected it")
  (is (not (mime/font? "application/font-off")))
  (is (mime/image? "image/svg+xml"))
  (is (mime/xml? "image/svg+xml"))
  (is (mime/scriptable? "application/pdf"))
  (is (not (mime/html? "application/xhtml+xml")))
  (is (mime/audio-or-video? "application/ogg"))
  (is (mime/json? "application/feed+json"))
  (is (not (some #(% nil) [mime/image? mime/audio-or-video? mime/font? mime/zip-based?
                          mime/archive? mime/xml? mime/html? mime/scriptable?
                          mime/javascript? mime/json?]))
      "nil is in no group"))

(deftest extract
  (is (= "text/html" (mime/serialize (mime/extract ["text/plain;charset=gbk" "text/html"])))
      "the last value, where wary-fetch took the first")
  (is (= "text/html" (mime/serialize (mime/extract "text/plain, text/html")))
      "values joined, as fetch joins them in a browser")
  (is (= "text/plain;charset=gbk" (mime/serialize (mime/extract ["text/plain;charset=gbk" "text/plain"])))
      "the charset of an earlier value of the same essence")
  (is (nil? (mime/extract nil)))
  (is (nil? (mime/extract [])))
  (is (nil? (mime/extract ["*/*" "nonsense"])))
  (testing "a charset after many parameters"
    (let [names (map #(str "p" %) (range 9))
          s     (apply str "a/b" (map #(str ";" % "=1") names))]
      (is (= (concat names ["charset"])
             (keys (:parameters (mime/extract ["a/b;charset=x" s]))))))))

(deftest nosniff?
  (is (mime/nosniff? "nosniff"))
  (is (mime/nosniff? ["NOSNIFF" "no"]))
  (is (not (mime/nosniff? ["no" "nosniff"])))
  (is (not (mime/nosniff? nil)))
  (is (not (mime/nosniff? "noſniff")) "the long s isn't an s"))
