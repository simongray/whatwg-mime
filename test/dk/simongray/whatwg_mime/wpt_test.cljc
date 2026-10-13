(ns dk.simongray.whatwg-mime.wpt-test
  "The library against the MIME type tests of web-platform-tests, from the
  files that dev/fetch.sh puts in dev-resources/wpt.

  WPT checks its media and sniffing files in a browser, so the types that
  this namespace expects of them come from the standard's tables."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dk.simongray.whatwg-mime :as mime]
            [dk.simongray.whatwg-mime.patterns :as patterns]
            [dk.simongray.whatwg-mime.test-data :as test-data]))

(defn cases
  "The tests of the WPT file `name`, without its comments."
  [name]
  (filter map? (test-data/json (str "wpt/" name))))

(deftest mime-types
  (doseq [{:strs [input output encoding] :as c}
          (concat (cases "mime-types.json") (cases "generated-mime-types.json"))]
    (testing (pr-str input)
      (is (= output (mime/serialize input)))
      (when (contains? c "encoding")
        (is (= encoding (mime/encoding input)) "encoding")))))

(def group-predicates
  "The predicate of each group, by its name in WPT."
  {"image"          mime/image?
   "audio or video" mime/audio-or-video?
   "font"           mime/font?
   "ZIP-based"      mime/zip-based?
   "archive"        mime/archive?
   "XML"            mime/xml?
   "HTML"           mime/html?
   "scriptable"     mime/scriptable?
   "JavaScript"     mime/javascript?
   "JSON"           mime/json?})

(defn expected-groups
  "The `groups` that WPT expects of the MIME type `input`, as a set. WPT
  still has application/font-off as a font, which the standard corrected
  to application/font-otf in July 2025 (whatwg/mimesniff#165)."
  [input groups]
  (if (str/starts-with? input "application/font-off")
    #{}
    (set groups)))

(deftest mime-groups
  (doseq [{:strs [input groups]} (cases "mime-groups.json")]
    (testing (pr-str input)
      (is (= (expected-groups input groups)
             (set (for [[group pred] group-predicates
                        :when (pred input)]
                    group)))))))

(deftest content-types
  (doseq [{:strs [contentType mimeType encoding]} (cases "content-types.json")]
    (testing (pr-str contentType)
      (is (= mimeType (mime/serialize (mime/extract contentType))) "separate")
      (is (= mimeType (mime/serialize (mime/extract (str/join ", " contentType)))) "joined")
      (is (= encoding (mime/encoding (mime/extract contentType))) "encoding"))))

;; a script served with nosniff runs only with a JavaScript MIME type
(deftest script-content-types
  (doseq [{:strs [contentType executes encoding]} (cases "script-content-types.json")]
    (testing (pr-str contentType)
      (let [m (mime/extract contentType)]
        (is (= executes (mime/javascript? m)))
        (is (= encoding (when executes (mime/encoding m))) "encoding")))))

(defn header-values
  "The values of the header `name` in the text `headers` (Name: value on
  each line), without their leading and trailing HTTP whitespace."
  [headers name]
  (for [line         (str/split headers #"\r?\n")
        :let         [[k v] (str/split line #":" 2)]
        :when        (= name (str/lower-case k))]
    (str/replace v #"^[\t\n\r ]+|[\t\n\r ]+$" "")))

(deftest x-content-type-options
  (doseq [{:strs [input nosniff]} (cases "x-content-type-options.json")]
    (testing (pr-str input)
      (is (= nosniff (mime/nosniff? (header-values input "x-content-type-options")))))))

(def media
  "The audio or video type of each of WPT's media files. The standard has
  no pattern for FLAC."
  {"mp3-raw.mp3"      "audio/mpeg"
   "mp3-with-id3.mp3" "audio/mpeg"
   "flac.flac"        nil
   "ogg.ogg"          "application/ogg"
   "mp4.mp4"          "video/mp4"
   "wav.wav"          "audio/wave"
   "webm.webm"        "video/webm"})

(deftest media-files
  (doseq [[file type] media
          :let        [b (test-data/bytes (str "wpt/media/" file))]
          :when       b]
    (testing file
      (is (= type (patterns/audio-or-video-type b)))
      (is (= (or type "application/octet-stream")
             (mime/essence (mime/sniff b "")))
          "served without a type"))))

;; WPT serves each as text/plain, which old versions of Apache sent for a file
;; of unknown type. It also gzips test-file.zip, but the gzip file is as
;; binary as the ZIP inside it.
(def sniffed
  "The computed type of each of WPT's sniffing files, served as their
  headers say."
  {"binary-data.bin"   "application/octet-stream"
   "png-image.png"     "application/octet-stream"
   "test-file.zip"     "application/octet-stream"
   "html-content.html" "text/plain"})

(deftest sniffing-files
  (doseq [[file type] sniffed
          :let        [b       (test-data/bytes (str "wpt/sniffing/" file))
                       headers (test-data/text (str "wpt/sniffing/" file ".headers"))]
          :when       b]
    (testing file
      (is (= type (mime/essence (mime/sniff b (header-values headers "content-type"))))))))
