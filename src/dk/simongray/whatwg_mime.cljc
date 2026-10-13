(ns dk.simongray.whatwg-mime
  "Parse and sniff MIME types the way browsers do, by the MIME Sniffing
  Standard.

  A MIME type is a plain map:

  - :type and :subtype, in lower case, e.g. \"text\" and \"html\"
  - :parameters, when there are any, a map of lower-case names to values
    in the order of the text

  The parameters can also be a vector of name-value pairs. Unlike the map,
  it keeps its order when you add a ninth parameter.

  Every function that takes a MIME type also takes its text, and treats
  text that doesn't parse as nil."
  (:require [clojure.string :as str]
            [dk.simongray.whatwg-mime.impl.labels :as labels]
            [dk.simongray.whatwg-mime.impl.parser :as parser]
            [dk.simongray.whatwg-mime.patterns :as patterns]))

;; MIME Sniffing, section 4.4
(defn parse
  "The MIME type in the text `s`, or nil when it doesn't parse.

      (parse \"Text/HTML; Charset=\\\"utf-8\\\"\")
      ;; => {:type \"text\" :subtype \"html\"
      ;;     :parameters {\"charset\" \"utf-8\"}}"
  [s]
  (some-> s str parser/parse))

(defn- ->mime
  "The MIME type `m`, parsed when it's text."
  [m]
  (if (or (nil? m) (map? m))
    m
    (parse m)))

;; MIME Sniffing, section 4.5
(defn serialize
  "The MIME type `m` as text, with each parameter value that isn't a token
  in quotes.

      (serialize \"Text/HTML; Charset=\\\"utf-8\\\"; x=(\")
      ;; => \"text/html;charset=utf-8;x=\\\"(\\\"\""
  [m]
  (some-> (->mime m) parser/serialize))

;; MIME Sniffing, section 4.2
(defn essence
  "The type and subtype of the MIME type `m`, e.g. text/html."
  [m]
  (when-let [{:keys [type subtype]} (->mime m)]
    (str type "/" subtype)))

(defn- parameter
  "The value of the parameter `name` of the MIME type `m`, or nil."
  [m name]
  (let [parameters (:parameters m)]
    (if (map? parameters)
      (get parameters name)
      (some (fn [[k v]] (when (= name k) v)) parameters))))

(defn charset
  "The charset parameter of the MIME type `m` as it's written, or nil."
  [m]
  (some-> (->mime m) (parameter "charset")))

;; Fetch Standard, section 3.5, "legacy extract an encoding", and Encoding
;; Standard, section 4.2, "get an encoding"
(defn encoding
  "The encoding that the charset of the MIME type `m` names, e.g.
  windows-1252 for latin1, or nil."
  [m]
  (some-> (charset m) labels/encoding))

;; MIME Sniffing, section 4.3
(defn valid?
  "Whether HTTP's grammar allows the text `s` as a MIME type, e.g.
  text/html but not text/html;."
  [s]
  (boolean (some-> s str parser/valid?)))

(defn- subtype-suffix?
  "Whether the subtype of the MIME type `m` ends in the `suffix`."
  [m suffix]
  (str/ends-with? (:subtype m) suffix))

;; MIME Sniffing, section 4.6
(defn image?
  "Whether the MIME type `m` is an image MIME type."
  [m]
  (= "image" (:type (->mime m))))

;; MIME Sniffing, section 4.6
(defn audio-or-video?
  "Whether the MIME type `m` is of audio or video, application/ogg
  included."
  [m]
  (let [m (->mime m)]
    (or (contains? #{"audio" "video"} (:type m))
        (= "application/ogg" (essence m)))))

;; MIME Sniffing, section 4.6
(defn font?
  "Whether the MIME type `m` is a font MIME type."
  [m]
  (let [m (->mime m)]
    (or (= "font" (:type m))
        (contains? #{"application/font-cff" "application/font-otf"
                     "application/font-sfnt" "application/font-ttf"
                     "application/font-woff" "application/vnd.ms-fontobject"
                     "application/vnd.ms-opentype"}
                   (essence m)))))

;; MIME Sniffing, section 4.6
(defn zip-based?
  "Whether the MIME type `m` is a ZIP-based MIME type, e.g. one with a +zip
  suffix."
  [m]
  (let [m (->mime m)]
    (boolean (and m (or (subtype-suffix? m "+zip")
                        (= "application/zip" (essence m)))))))

;; MIME Sniffing, section 4.6
(defn archive?
  "Whether the MIME type `m` is an archive MIME type: ZIP, gzip or RAR."
  [m]
  (contains? #{"application/x-rar-compressed" "application/zip"
               "application/x-gzip"}
             (essence m)))

;; MIME Sniffing, section 4.6
(defn xml?
  "Whether the MIME type `m` is an XML MIME type, e.g. one with a +xml
  suffix."
  [m]
  (let [m (->mime m)]
    (boolean (and m (or (subtype-suffix? m "+xml")
                        (contains? #{"text/xml" "application/xml"} (essence m)))))))

;; MIME Sniffing, section 4.6
(defn html?
  "Whether the MIME type `m` is text/html (application/xhtml+xml is XML)."
  [m]
  (= "text/html" (essence m)))

;; MIME Sniffing, section 4.6
(defn scriptable?
  "Whether the MIME type `m` is a scriptable MIME type: XML, HTML or PDF."
  [m]
  (let [m (->mime m)]
    (or (xml? m)
        (html? m)
        (= "application/pdf" (essence m)))))

;; MIME Sniffing, section 4.6
(defn javascript?
  "Whether the MIME type `m` is a JavaScript MIME type, e.g.
  text/javascript or application/x-javascript."
  [m]
  (contains? #{"application/ecmascript" "application/javascript"
               "application/x-ecmascript" "application/x-javascript"
               "text/ecmascript" "text/javascript" "text/javascript1.0"
               "text/javascript1.1" "text/javascript1.2" "text/javascript1.3"
               "text/javascript1.4" "text/javascript1.5" "text/jscript"
               "text/livescript" "text/x-ecmascript" "text/x-javascript"}
             (essence m)))

;; MIME Sniffing, section 4.6
(defn json?
  "Whether the MIME type `m` is a JSON MIME type, e.g. one with a +json
  suffix."
  [m]
  (let [m (->mime m)]
    (boolean (and m (or (subtype-suffix? m "+json")
                        (contains? #{"application/json" "text/json"} (essence m)))))))

;; Fetch Standard, section 2.2.2, "get, decode, and split", given the values
;; as text
(defn- split-values
  "The `values` of a header (a string or a seq of strings), split at the
  commas outside quotes, or nil for none."
  [values]
  (let [values (if (string? values) [values] values)]
    (when (seq values)
      (parser/split-values (str/join ", " values)))))

(defn- with-parameter
  "The MIME type `m` with the parameter `name` set to `value`, after the
  others."
  [m name value]
  (assoc m :parameters (parser/ordered-map (concat (:parameters m) [[name value]]))))

;; Fetch Standard, section 3.5, "extract a MIME type", step 6
(defn- extract-value
  "The `state` of an extract (the MIME type so far, its essence and the
  charset that it carries) after the Content-Type value `s`."
  [[_ essence-so-far charset :as state] s]
  (let [value (parse s)
        e     (essence value)]
    (cond
      (or (nil? value) (= "*/*" e))
      state

      (not= essence-so-far e)
      [value e (parameter value "charset")]

      (and charset (nil? (parameter value "charset")))
      [(with-parameter value "charset" charset) e charset]

      :else
      [value e charset])))

;; Fetch Standard, section 3.5, "extract a MIME type"
(defn extract
  "The MIME type of a response with the Content-Type `values` (a string or
  a seq of strings), or nil when none of them parses.

  It's the last value that parses, other than */*. When it has no charset,
  it takes that of an earlier value with the same essence.

      (extract [\"text/html;charset=gbk;a=b\" \"text/html;x=y\"])
      ;; => {:type \"text\" :subtype \"html\"
      ;;     :parameters {\"x\" \"y\" \"charset\" \"gbk\"}}"
  [values]
  (first (reduce extract-value [nil nil nil] (split-values values))))

;; Fetch Standard, section 3.6, "determine nosniff"
(defn nosniff?
  "Whether the X-Content-Type-Options `values` (a string or a seq of
  strings) forbid sniffing: whether the first is nosniff, in any case."
  [values]
  (= "nosniff" (some-> (first (split-values values)) parser/ascii-lower-case)))

;; MIME Sniffing, section 5.1
(defn- apache-bug?
  "Whether the last of the Content-Type `values` is one that old versions
  of Apache sent for a file of unknown type."
  [values]
  (contains? #{"text/plain" "text/plain; charset=ISO-8859-1"
               "text/plain; charset=iso-8859-1" "text/plain; charset=UTF-8"}
             (cond
               (string? values)     values
               (sequential? values) (last values))))

;; MIME Sniffing, section 7, but with the Content-Type as Fetch extracts it
;; rather than its last value, as browsers do
(defn sniff
  "The MIME type that a browser treats a resource as, by its first bytes
  `b` and its `content-type`, with the `opts`:

  - :no-sniff?, when X-Content-Type-Options says nosniff

  The bytes are a byte array on the JVM and a Uint8Array in ClojureScript.
  Only the first 1445 count. The Content-Type is its values (as extract
  takes them), a MIME type or nil.

  The result is the Content-Type unless it's missing or unknown, or it's an
  image, audio or video type that the bytes contradict. HTML and XML always
  stay.

      (sniff (.getBytes \"<!DOCTYPE html><title>Hi</title>\") nil)
      ;; => {:type \"text\" :subtype \"html\"}

  For an image or audio element, use the tables in patterns."
  ([b]
   (sniff b nil))
  ([b content-type]
   (sniff b content-type {}))
  ([b content-type {:keys [no-sniff?] :as opts}]
   (let [supplied (if (map? content-type) content-type (extract content-type))]
     (cond
       (or (xml? supplied) (html? supplied))
       supplied

       (or (nil? supplied)
           (contains? #{"unknown/unknown" "application/unknown" "*/*"} (essence supplied)))
       (parse (patterns/unknown-type b (not no-sniff?)))

       no-sniff?
       supplied

       (apache-bug? content-type)
       (parse (patterns/text-or-binary b))

       :else
       (or (some-> (when (image? supplied) (patterns/image-type b)) parse)
           (some-> (when (audio-or-video? supplied) (patterns/audio-or-video-type b)) parse)
           supplied)))))

(comment
  (parse "text/html;charset=\"shift_jis\"iso-2022-jp")
  (serialize {:type "text" :subtype "plain" :parameters [["a" "1"] ["b" "x y"]]})
  (extract ["text/plain;charset=gbk" "text/plain"])
  (nosniff? ["NOSNIFF" "no"])
  (sniff (.getBytes "%PDF-1.7") "application/unknown")
  #_.)
