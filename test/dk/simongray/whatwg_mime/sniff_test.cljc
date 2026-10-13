(ns dk.simongray.whatwg-mime.sniff-test
  "The tables and rules of sniffing, with inputs written by hand from the
  standard, so that a typo in a table fails a test. Each row gets a match
  and some near misses, and each step of sniff a case."
  (:require [clojure.test :refer [deftest is testing]]
            [dk.simongray.whatwg-mime :as mime]
            [dk.simongray.whatwg-mime.octets :refer [octets]]
            [dk.simongray.whatwg-mime.patterns :as patterns]))

(defn- check
  "Check that `f` returns the type of each of the `cases`, a vector of a
  description, the parts of the bytes (as octets takes them) and the type."
  [f cases]
  (doseq [[description parts type] cases]
    (testing description
      (is (= type (f (apply octets parts)))))))

(deftest image-type
  (check patterns/image-type
         [["Windows icon" [[0 0 1 0]] "image/x-icon"]
          ["Windows cursor" [[0 0 2 0]] "image/x-icon"]
          ["BMP" ["BM"] "image/bmp"]
          ["BMP, cut short" ["B"] nil]
          ["GIF87a" ["GIF87a"] "image/gif"]
          ["GIF89a" ["GIF89a"] "image/gif"]
          ["GIF in lower case" ["gif89a"] nil]
          ["GIF88a" ["GIF88a"] nil]
          ["WebP" ["RIFF" [1 2 3 4] "WEBPVP8 "] "image/webp"]
          ["WAVE is no image" ["RIFF" [1 2 3 4] "WAVEfmt "] nil]
          ["PNG" [0x89 "PNG" [0x0D 0x0A 0x1A 0x0A]] "image/png"]
          ["JPEG" [[0xFF 0xD8 0xFF 0xE0]] "image/jpeg"]
          ["JPEG, cut short" [[0xFF 0xD8]] nil]
          ["whitespace before an image" [" GIF89a"] nil]
          ["nothing" [] nil]]))

(defn- ftyp
  "An ftyp box of MP4 with the `major` brand and the `compatible` brands,
  each of four letters."
  [major & compatible]
  [[0 0 0 (+ 16 (* 4 (count compatible)))] "ftyp" major [0 0 0 0] (apply str compatible)])

(defn- ebml
  "The start of an EBML file whose DocType element holds the text
  `doctype` after `padding` zero bytes."
  [doctype padding]
  [[0x1A 0x45 0xDF 0xA3 0x9F 0x42 0x86 0x81 0x01 0x42 0x82]
   (bit-or 0x80 (+ padding (count doctype)))
   (repeat padding 0)
   doctype
   [0x42 0x87 0x81 0x04]])

(defn- frames
  "Two frames of MPEG audio whose headers are the bytes `header`, with
  zeros that make the first `size` bytes long."
  [header size]
  [header (repeat (- size 4) 0) header])

(deftest audio-or-video-type
  (check patterns/audio-or-video-type
         [["AIFF" ["FORM" [0 0 0 0] "AIFF"] "audio/aiff"]
          ["MP3 with ID3" ["ID3" [4 0]] "audio/mpeg"]
          ["Ogg" ["OggS" 0] "application/ogg"]
          ["Ogg, cut short" ["OggS"] nil]
          ["MIDI" ["MThd" [0 0 0 6]] "audio/midi"]
          ["MIDI with a header of another size" ["MThd" [0 0 0 7]] nil]
          ["AVI" ["RIFF" [0 0 0 0] "AVI "] "video/avi"]
          ["WAVE" ["RIFF" [0 0 0 0] "WAVE"] "audio/wave"]
          ["MP4 of the major brand mp42" (ftyp "mp42" "isom") "video/mp4"]
          ["MP4 of a compatible brand mp41" (ftyp "isom" "iso2" "mp41") "video/mp4"]
          ["M4A of no mp4 brand" (ftyp "M4A " "isom" "M4A ") nil]
          ["MP4 whose box is larger than the bytes" [[0 0 1 0] "ftypmp42"] nil]
          ["MP4 whose box size isn't a multiple of 4" [[0 0 0 13] "ftypmp42" [0 0 0 0 0]] nil]
          ["WebM" (ebml "webm" 0) "video/webm"]
          ["WebM, padded" (ebml "webm" 2) "video/webm"]
          ["Matroska" (ebml "matroska" 0) nil]
          ["MP3 of MPEG-1" (frames [0xFF 0xFB 0x90 0x00] 417) "audio/mpeg"]
          ["MP3 of MPEG-1, padded" (frames [0xFF 0xFB 0x92 0x00] 418) "audio/mpeg"]
          ["MP3 of MPEG-2" (frames [0xFF 0xF3 0x80 0x00] 208) "audio/mpeg"]
          ["MP3 of MPEG-2.5" (frames [0xFF 0xE3 0x80 0x00] 417) "audio/mpeg"]
          ["MP3 whose second frame is a byte off" (frames [0xFF 0xFB 0x90 0x00] 416) nil]
          ["one frame of MP3" [[0xFF 0xFB 0x90 0x00] (repeat 500 0)] nil]
          ["MPEG audio of layer II" (frames [0xFF 0xFD 0x90 0x00] 417) nil]
          ["MP3 of the bit rate 15" (frames [0xFF 0xFB 0xF0 0x00] 417) nil]]))

(deftest font-type
  (check patterns/font-type
         [["Embedded OpenType" [(repeat 34 7) "LP"] "application/vnd.ms-fontobject"]
          ["TrueType" [[0 1 0 0]] "font/ttf"]
          ["OpenType" ["OTTO"] "font/otf"]
          ["TrueType collection" ["ttcf"] "font/collection"]
          ["WOFF" ["wOFF"] "font/woff"]
          ["WOFF2" ["wOF2"] "font/woff2"]
          ["WOFF in upper case" ["WOFF"] nil]]))

(deftest archive-type
  (check patterns/archive-type
         [["gzip" [[0x1F 0x8B 0x08]] "application/x-gzip"]
          ["ZIP" ["PK" [3 4]] "application/zip"]
          ["RAR 4" ["Rar!" [0x1A 0x07 0x00]] "application/x-rar-compressed"]
          ["RAR 5" ["Rar!" [0x1A 0x07 0x01 0x00]] nil]]))

(deftest unknown-type
  (testing "with the scriptable types"
    (check #(patterns/unknown-type % true)
           [["a doctype" ["<!DOCTYPE HTML>"] "text/html"]
            ["a doctype in lower case" ["<!doctype html "] "text/html"]
            ["a doctype without its space" ["<!DOCTYPEhtml>"] "text/plain"]
            ["whitespace first" [[0x09 0x0A 0x0C 0x0D 0x20] "<html>"] "text/html"]
            ["a tag without its end" ["<html"] "text/plain"]
            ["a tag ended by a slash" ["<br/>"] "text/plain"]
            ["html" ["<HtMl>"] "text/html"]
            ["head" ["<head>"] "text/html"]
            ["script" ["<script "] "text/html"]
            ["iframe" ["<IFRAME>"] "text/html"]
            ["h1" ["<H1>"] "text/html"]
            ["div" ["<div>"] "text/html"]
            ["font" ["<font>"] "text/html"]
            ["table" ["<table>"] "text/html"]
            ["a" ["<a href=x>"] "text/html"]
            ["style" ["<style>"] "text/html"]
            ["title" ["<title>"] "text/html"]
            ["b" ["<b>"] "text/html"]
            ["body" ["<body>"] "text/html"]
            ["br" ["<br>"] "text/html"]
            ["p" ["<p>"] "text/html"]
            ["a comment" ["<!-- x -->"] "text/html"]
            ["a comment without a space" ["<!--x-->"] "text/plain"]
            ["XML" ["  <?xml version=\"1.0\"?>"] "text/xml"]
            ["XML in upper case" ["<?XML"] "text/plain"]
            ["PDF" ["%PDF-1.7"] "application/pdf"]
            ["PDF after whitespace" [" %PDF-1.7"] "text/plain"]]))
  (testing "without the scriptable types"
    (check patterns/unknown-type
           [["HTML" ["<html>"] "text/plain"]
            ["PDF" ["%PDF-1.7"] "text/plain"]
            ["PostScript" ["%!PS-Adobe-3.0"] "application/postscript"]
            ["UTF-16BE" [[0xFE 0xFF 0 0x68]] "text/plain"]
            ["UTF-16LE" [[0xFF 0xFE 0x68 0]] "text/plain"]
            ["UTF-8 with a NUL" [[0xEF 0xBB 0xBF 0]] "text/plain"]
            ["an image" [[0x89] "PNG" [0x0D 0x0A 0x1A 0x0A]] "image/png"]
            ["audio" ["ID3" [4 0]] "audio/mpeg"]
            ["an archive" ["PK" [3 4]] "application/zip"]
            ["text" ["Hello"] "text/plain"]
            ["text with an escape" ["Hello" 0x1B] "text/plain"]
            ["text with a vertical tab" ["Hello" 0x0B] "application/octet-stream"]
            ["text with a NUL" ["Hello" 0] "application/octet-stream"]
            ["nothing" [] "text/plain"]])))

(deftest text-or-binary
  (check patterns/text-or-binary
         [["UTF-16BE" [[0xFE 0xFF 0]] "text/plain"]
          ["UTF-16LE" [[0xFF 0xFE 0]] "text/plain"]
          ["UTF-8" [[0xEF 0xBB 0xBF 0]] "text/plain"]
          ["text" ["Hello"] "text/plain"]
          ["HTML" ["<html>"] "text/plain"]
          ["a NUL" [0] "application/octet-stream"]
          ["a PNG" [[0x89] "PNG" [0x0D 0x0A 0x1A 0x0A]] "application/octet-stream"]]))

(deftest feed-type
  (check patterns/feed-type
         [["RSS" ["<rss version=\"2.0\">"] "application/rss+xml"]
          ["Atom" ["<feed xmlns=\"http://www.w3.org/2005/Atom\">"] "application/atom+xml"]
          ["RSS after a byte order mark, a declaration, an instruction, a comment and a doctype"
           [[0xEF 0xBB 0xBF] "<?xml version=\"1.0\"?>\n<?xml-stylesheet href=\"s.xsl\"?>\n"
            "<!-- a > b -->\n<!DOCTYPE rss>\n<rss>"]
           "application/rss+xml"]
          ["RSS 1.0" ["<rdf:RDF xmlns=\"http://purl.org/rss/1.0/\""
                      " xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">"]
           "application/rss+xml"]
          ["RSS 1.0, its namespaces the other way round"
           ["<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\""
            " xmlns=\"http://purl.org/rss/1.0/\">"]
           "application/rss+xml"]
          ["RDF that isn't RSS" ["<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">"] nil]
          ["an element whose name only starts with rss" ["<rssx>"] "application/rss+xml"]
          ["a page" ["<!DOCTYPE html><html>"] nil]
          ["a comment that doesn't end" ["<!-- <rss>"] nil]
          ["text before the feed" ["Hello <rss>"] nil]
          ["RSS past the resource header" ["<!--" (repeat 1450 0x78) "--><rss>"] nil]
          ["RSS just inside the resource header" ["<!--" (repeat 1430 0x78) "--><rss>"]
           "application/rss+xml"]]))

(def png
  "The signature of PNG."
  [[0x89] "PNG" [0x0D 0x0A 0x1A 0x0A]])

(defn- sniffed
  "The essence of what sniff returns for the bytes of the `parts`, with
  `content-type` and `opts`."
  ([parts content-type]
   (sniffed parts content-type {}))
  ([parts content-type opts]
   (mime/essence (mime/sniff (apply octets parts) content-type opts))))

(deftest sniff
  (testing "XML and HTML stay as they are"
    (is (= "image/svg+xml" (sniffed png "image/svg+xml")))
    (is (= "text/html" (sniffed png "text/html"))))
  (testing "an unknown type gets sniffed"
    (doseq [content-type [nil "" "unknown/unknown" "application/unknown" "*/*" "nonsense"]]
      (is (= "text/html" (sniffed ["<p>"] content-type)) (pr-str content-type))))
  (testing "nosniff"
    (is (= "text/plain" (sniffed ["<p>"] nil {:no-sniff? true})) "finds no HTML")
    (is (= "image/png" (sniffed png nil {:no-sniff? true})) "finds an image")
    (is (= "image/gif" (sniffed png "image/gif" {:no-sniff? true})) "keeps the type"))
  (testing "the types that old versions of Apache sent"
    (doseq [content-type ["text/plain" "text/plain; charset=ISO-8859-1"
                          "text/plain; charset=iso-8859-1" "text/plain; charset=UTF-8"]]
      (is (= "application/octet-stream" (sniffed png content-type)) content-type)
      (is (= "text/plain" (sniffed ["<p>"] content-type)) content-type))
    (is (= "application/octet-stream" (sniffed png ["text/html" "text/plain"])) "as the last value")
    (is (= "text/plain" (sniffed png "text/plain;charset=UTF-8")) "only when exact"))
  (testing "an image"
    (is (= "image/png" (sniffed png "image/gif")))
    (is (= "image/gif" (sniffed ["Hello"] "image/gif")) "that the bytes don't say"))
  (testing "audio and video"
    (is (= "audio/mpeg" (sniffed ["ID3" [4 0]] "audio/x-unknown")))
    (is (= "application/octet-stream" (sniffed ["ID3" [4 0]] "application/octet-stream"))
        "served as a download"))
  (testing "the supplied type with its parameters"
    (is (= {:type "text" :subtype "plain" :parameters {"charset" "utf-8"}}
           (mime/sniff (octets "Hello") "text/plain; charset=utf-8")))
    (is (= {:type "application" :subtype "json"}
           (mime/sniff (octets "{}") {:type "application" :subtype "json"})))))
