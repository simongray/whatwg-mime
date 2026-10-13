whatwg-mime
===========

[![Clojars Project](https://img.shields.io/clojars/v/dk.simongray/whatwg-mime.svg)](https://clojars.org/dk.simongray/whatwg-mime)

This library implements the
[WHATWG MIME Sniffing Standard](https://mimesniff.spec.whatwg.org/) in
Clojure and ClojureScript. Browsers follow it when they read a
Content-Type and when they work out what a response really is, so you get
the answer that a browser would, as plain data.

- **The browser's reading of a Content-Type.** The charset of
  `text/html; x="charset=evil"; charset=utf-8` is utf-8. Of two
  Content-Types, the last one that parses counts, as in the
  [Fetch Standard](https://fetch.spec.whatwg.org/#content-type-header).
- **Sniffing.** Tell HTML, XML, PDF, images, audio, video, fonts and
  archives apart by their first bytes when the Content-Type is missing or
  wrong. The rules for a feed served as HTML are here too, though the
  standard has dropped them.
- **Encodings by their names on the web.** A charset of latin1 means
  windows-1252, as in every browser, and not ISO-8859-1 as on the JVM.
- **The same results everywhere.** One codebase runs on the JVM, in Node
  and in browsers. It needs nothing but Clojure and passes the MIME type
  tests of [web-platform-tests](https://github.com/web-platform-tests/wpt/tree/master/mimesniff).

> This library is meant to replace the MIME type code of wary-fetch,
> websub-clj and podcast-clj, which each read MIME types their own way.
> Like them, it was developed with assistance from frontier LLMs.

Getting started
---------------

The library needs Clojure 1.11+ and Java 11+. Add the latest release from
[Clojars](https://clojars.org/dk.simongray/whatwg-mime) to the `:deps` of
your `deps.edn`:

```clojure
dk.simongray/whatwg-mime {:mvn/version "0.1.0"}
```

For changes that aren't released yet, use the SHA of the latest commit on
`master` instead. In shadow-cljs a Git dependency only works through
`deps.edn`, so set `:deps true` in your `shadow-cljs.edn` too.

MIME types
----------

Parse a MIME type with `mime/parse`, and write it with `mime/serialize`:

```clojure
(require '[dk.simongray.whatwg-mime :as mime])

(mime/parse "Text/HTML; Charset=\"utf-8\"")
;; => {:type "text" :subtype "html" :parameters {"charset" "utf-8"}}

(mime/serialize "Text/HTML; Charset=\"utf-8\"; x=(")
;; => "text/html;charset=utf-8;x=\"(\""
```

For text that isn't a MIME type, `mime/parse` returns nil. The other
functions take a MIME type or its text, e.g. `mime/essence` returns
text/html for `"Text/HTML; charset=utf-8"`.

The charset of a MIME type is a label, and `mime/encoding` returns the
name of the encoding that it stands for:

```clojure
(mime/charset "text/html; charset=latin1")
;; => "latin1"

(mime/encoding "text/html; charset=latin1")
;; => "windows-1252"
```

In ClojureScript, `TextDecoder` takes that name. On the JVM, most names
are those of Java charsets too, but macintosh is x-MacRoman, and the JDK
lacks a few (e.g. ISO-8859-10).

The groups of the standard are predicates, e.g. `mime/html?`, `mime/xml?`,
`mime/json?`, `mime/javascript?`, `mime/image?` and `mime/audio-or-video?`:

```clojure
(mime/xml? "application/rss+xml")
;; => true
```

Content-Type headers
--------------------

A response can have more than one Content-Type, and browsers read them
all. Pass the values to `mime/extract`, as a string or a vector:

```clojure
(mime/extract ["text/plain;charset=gbk" "text/plain"])
;; => {:type "text" :subtype "plain" :parameters {"charset" "gbk"}}
```

It returns the last value that parses. When that has no charset, it takes
the charset of an earlier value of the same type. Read
X-Content-Type-Options with `mime/nosniff?`.

Sniffing
--------

Pass the first bytes of a response to `mime/sniff`, with its
Content-Type, to get the MIME type that a browser would treat it as. The
bytes are a byte array on the JVM or a Uint8Array in ClojureScript:

```clojure
(mime/sniff (.getBytes "<!DOCTYPE html><title>Hi</title>") nil)
;; => {:type "text" :subtype "html"}

(mime/sniff (.getBytes "GIF89a") "image/png")
;; => {:type "image" :subtype "gif"}
```

Only the first 1445 bytes count, so you can pass a whole body. The
Content-Type stays as it is unless it's missing or unknown, or it's an
image, audio or video type that the bytes contradict. HTML and XML always
stay. When X-Content-Type-Options says nosniff, pass `{:no-sniff? true}`
too.

The [`patterns`](src/dk/simongray/whatwg_mime/patterns.cljc) namespace
holds the tables of the standard, for when you know what you're looking
for. Its `audio-or-video-type` finds MP3, MP4, WebM, Ogg and WAV files
whatever their Content-Type, and `feed-type` finds an RSS or Atom feed
served as HTML:

```clojure
(require '[dk.simongray.whatwg-mime.patterns :as patterns])

(patterns/feed-type (.getBytes "<?xml version=\"1.0\"?>\n<rss version=\"2.0\">"))
;; => "application/rss+xml"
```

The standard dropped those rules for feeds in 2024, since no browser
follows them any more, but a crawler still needs them.

Valid MIME types
----------------

Like browsers, the parser is lenient: it drops a parameter that it can't
read rather than fail. To check a MIME type that someone else wrote, use
`mime/valid?`, which follows the grammar of HTTP:

```clojure
(mime/valid? "text/html;charset=utf-8")
;; => true

(mime/valid? "text/html;")
;; => false
```

The standard names no validation errors, so the library can't say what's
wrong.

Where the library departs from the standard
-------------------------------------------

- **The Content-Type as Fetch reads it.** Sniffing starts from the type
  that `mime/extract` returns rather than from the last Content-Type as
  it is, as browsers do.
- **Every type is supported.** The standard sniffs an image, audio or
  video type only when the browser can play or show it. A library does
  neither, so it sniffs them all.
- **MP3 and WebM.** As the standard writes them, its steps for MP3
  without ID3 and for WebM reject the media files of WPT. The library
  follows what they evidently mean and cites the open issues of the
  standard.

Development
-----------

```bash
dev/fetch.sh                                          # once, for the test data
clojure -X:test                                       # the tests on the JVM
npm install                                           # once, for the Node tests
clojure -M:cljs compile test                          # the tests in Node
clojure -M:bench -m dk.simongray.whatwg-mime.bench    # benchmarks on the JVM
clojure -M:cljs release bench && node target/bench.js # benchmarks in Node
```

The fetch script downloads the test data of web-platform-tests and the
labels of the Encoding Standard into `dev-resources/` (which Git ignores),
at the versions that the library follows. Without these files the
conformance tests have nothing to check.

The public namespaces are the root and `patterns`. The internal ones are
under `impl`:

- `impl.parser`, which parses and writes MIME types and splits the values
  of a header
- `impl.labels`, the labels of the Encoding Standard
- `impl.bytes`, the bytes on each platform
- `impl.media`, the signatures of MP4, WebM and MP3
- `impl.feed`, the rules for feeds that the standard dropped

License
-------

The whatwg-mime project is licensed under the [MIT licence](LICENSE).
