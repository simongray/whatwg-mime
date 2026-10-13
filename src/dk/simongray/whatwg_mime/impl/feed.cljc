(ns ^:no-doc dk.simongray.whatwg-mime.impl.feed
  "The rules for a feed served as HTML, from section 7.3 of the MIME
  Sniffing Standard. Commit b47be44 of whatwg/mimesniff removed them on
  15 July 2024, since no browser follows them.

  Each step reads the first `n` bytes of `b` from an index."
  (:require [dk.simongray.whatwg-mime.impl.bytes :as bytes]))

(def rss-namespace
  "The namespace of RSS 1.0."
  "http://purl.org/rss/1.0/")

(def rdf-namespace
  "The namespace of RDF."
  "http://www.w3.org/1999/02/22-rdf-syntax-ns#")

(defn- skip-past
  "The index just past the ASCII text `s`, found from `i` in the first `n`
  bytes of `b`, or nil when it isn't there."
  [b ^long n ^long i s]
  (loop [i i]
    (cond
      (>= i n)                  nil
      (bytes/ascii-at? b n i s) (+ i (count s))
      :else                     (recur (inc i)))))

(defn- tag-start
  "The index after a < at `i` in the first `n` bytes of `b`, after any
  whitespace, or nil when something else comes first."
  [b ^long n ^long i]
  (let [i (loop [i i]
            (if (and (< i n) (bytes/whitespace-byte? (bytes/byte-at b i)))
              (recur (inc i))
              i))]
    (when (and (< i n) (== 0x3C (bytes/byte-at b i)))
      (inc i))))

(defn- markup?
  "Whether a comment, declaration or processing instruction starts at `i`
  in the first `n` bytes of `b`, just after its <."
  [b ^long n ^long i]
  (or (bytes/ascii-at? b n i "!") (bytes/ascii-at? b n i "?")))

(defn- markup-end
  "The index after the comment, declaration or processing instruction that
  starts at `i` in the first `n` bytes of `b`, or nil when the bytes end
  first."
  [b ^long n ^long i]
  (cond
    (bytes/ascii-at? b n i "!--") (skip-past b n (+ i 3) "-->")
    (bytes/ascii-at? b n i "!")   (skip-past b n (+ i 1) ">")
    :else                         (skip-past b n (+ i 1) "?>")))

(defn- rss-1-namespaces?
  "Whether the namespaces of RSS 1.0 and RDF both come after `i` in the
  first `n` bytes of `b`, in either order."
  [b ^long n ^long i]
  (loop [i i]
    (cond
      (>= i n)
      false

      (bytes/ascii-at? b n i rss-namespace)
      (some? (skip-past b n (+ i (count rss-namespace)) rdf-namespace))

      (bytes/ascii-at? b n i rdf-namespace)
      (some? (skip-past b n (+ i (count rdf-namespace)) rss-namespace))

      :else
      (recur (inc i)))))

(defn- root-type
  "The feed type of the root element whose name starts at `i` in the first
  `n` bytes of `b`, or nil when it's no feed."
  [b ^long n ^long i]
  (cond
    (bytes/ascii-at? b n i "rss")
    "application/rss+xml"

    (bytes/ascii-at? b n i "feed")
    "application/atom+xml"

    (and (bytes/ascii-at? b n i "rdf:RDF")
         (rss-1-namespaces? b n (+ i 7)))
    "application/rss+xml"))

;; MIME Sniffing until 15 July 2024, section 7.3, "rules for distinguishing
;; if a resource is a feed or HTML"
(defn feed-type
  "The type of the feed in the first `n` bytes of `b`, or nil when there's
  none."
  [b ^long n]
  (loop [i (if (bytes/bytes-at? b n 0 [0xEF 0xBB 0xBF]) 3 0)]
    (when-let [i (tag-start b n i)]
      (if (markup? b n i)
        (when-let [end (markup-end b n i)]
          (recur (long end)))
        (root-type b n i)))))
