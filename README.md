whatwg-mime
===========

[![Clojars Project](https://img.shields.io/clojars/v/dk.simongray/whatwg-mime.svg)](https://clojars.org/dk.simongray/whatwg-mime)

This library implements the
[WHATWG MIME Sniffing Standard](https://mimesniff.spec.whatwg.org/) in
Clojure and ClojureScript. Browsers follow it when they read a
Content-Type and when they work out what a response really is, so you get
the answer that a browser would, as plain data.

- **The browser's reading of a Content-Type.** The charset of
  `text/html; x="charset=evil"; charset=utf-8` is utf-8. When a response
  has two Content-Types, the last one that parses counts, as in the
  [Fetch Standard](https://fetch.spec.whatwg.org/#content-type-header).
- **Sniffing.** Tell HTML, XML, PDF, images, audio, video, fonts,
  archives and feeds apart by their first bytes when the Content-Type is
  missing or wrong.
- **Encodings by their names on the web.** A charset of latin1 means
  windows-1252, as in every browser, and not ISO-8859-1 as on the JVM.
- **The same results everywhere.** One codebase runs on the JVM, in Node
  and in browsers. It needs nothing but Clojure and passes the MIME type
  tests of [web-platform-tests](https://github.com/web-platform-tests/wpt/tree/master/mimesniff).

> This library replaces the MIME type code of wary-fetch, websub-clj and
> podcast-clj, which each used to read MIME types their own way. Like
> them, it was developed with assistance from frontier LLMs.

Getting started
---------------

The library needs Clojure 1.11+ and Java 11+. Add the latest release from
[Clojars](https://clojars.org/dk.simongray/whatwg-mime) to the `:deps` of
your `deps.edn`:

```clojure
dk.simongray/whatwg-mime {:mvn/version "0.2.1"}
```

For changes that aren't released yet, use the SHA of the latest commit on
`master` instead. In shadow-cljs a Git dependency only works through
`deps.edn`, so set `:deps true` in your `shadow-cljs.edn` too.

MIME types
----------

Parse a MIME type with `mime/parse`, and turn it back into text with
`mime/serialize`:

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

Each encoding has several labels, e.g. latin1 for windows-1252. Use `mime/charset` for the label in a MIME type and
`mime/encoding` for the encoding that it stands for:

```clojure
(mime/charset "text/html; charset=latin1")
;; => "latin1"

(mime/encoding "text/html; charset=latin1")
;; => "windows-1252"
```

For a label on its own, e.g. from a meta tag, use `mime/label->encoding`.
To decode bytes in the encoding of a label, use `mime/decode`, which goes
beyond the standard:

```clojure
(mime/decode (.getBytes "Blåbær" "windows-1252") "latin1")
;; => "Blåbær"
```

It decodes windows-1252, which browsers use for Latin-1 and ASCII, the
same way everywhere. For other encodings it uses the platform's decoders,
so the text can differ slightly from a browser's.

Each group of MIME types in the standard has a predicate, e.g.
`mime/html?`, `mime/xml?`, `mime/json?`, `mime/javascript?`,
`mime/image?` and `mime/audio-or-video?`.

Content-Type headers
--------------------

A response can have more than one Content-Type, and browsers look at all
of them. Pass the values to `mime/extract` as a string or a vector:

```clojure
(mime/extract ["text/plain;charset=gbk" "text/plain"])
;; => {:type "text" :subtype "plain" :parameters {"charset" "gbk"}}
```

It returns the last value that parses. When that has no charset, it takes
the charset of an earlier value of the same type.

Sniffing
--------

To get the MIME type that a browser would treat a response as, pass its
first bytes and its Content-Type to `mime/sniff`. The bytes are a byte
array on the JVM or a Uint8Array in ClojureScript:

```clojure
(mime/sniff (.getBytes "<!DOCTYPE html><title>Hi</title>") nil)
;; => {:type "text" :subtype "html"}

(mime/sniff (.getBytes "GIF89a") "image/png")
;; => {:type "image" :subtype "gif"}
```

Only the first 1445 bytes count, so you can pass a whole body. The
Content-Type stays as it is unless it's missing or unknown, or it's an
image, audio or video type that the bytes contradict. HTML and XML always
stay. When X-Content-Type-Options says nosniff, which `mime/nosniff?`
checks, pass `{:no-sniff? true}` too.

When you know what kind of resource to expect, use the tables of the
standard in the [`patterns`](src/dk/simongray/whatwg_mime/patterns.cljc)
namespace. For example, `audio-or-video-type` finds MP3, MP4, WebM, Ogg
and WAV files whatever their Content-Type, and `feed-type` finds an RSS
or Atom feed served as HTML:

```clojure
(require '[dk.simongray.whatwg-mime.patterns :as patterns])

(patterns/feed-type (.getBytes "<?xml version=\"1.0\"?>\n<rss version=\"2.0\">"))
;; => "application/rss+xml"
```

The standard dropped its rules for feeds in 2024, because browsers no
longer follow them. Crawlers still need them.

Valid MIME types
----------------

Like browsers, the parser is lenient: it drops a parameter that it can't
parse rather than fail. To check a MIME type that someone else wrote, use
`mime/valid?`, which follows the grammar of HTTP:

```clojure
(mime/valid? "text/html;charset=utf-8")
;; => true

(mime/valid? "text/html;")
;; => false
```

The standard defines no validation errors, so `mime/valid?` can't say
what's wrong.

Where the library departs from the standard
-------------------------------------------

- **The Content-Type as Fetch reads it.** Like browsers, sniffing starts
  from the type that `mime/extract` returns, not from the last
  Content-Type as it's written.
- **Every type is supported.** The standard sniffs an image, audio or
  video type only when the browser supports it. Outside a browser, the
  library sniffs them all.
- **MP3 and WebM.** The standard's steps for WebM and for MP3 without ID3
  reject WPT's own media files. The library follows what the steps
  evidently mean and cites the open issues.

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
Encoding Standard into `dev-resources/` (which Git ignores) at the
versions that the library follows. Without these files the conformance
tests have nothing to check.

The public namespaces are the root and `patterns`. The internal ones are
under `impl`:

- `impl.parser`, which parses and serializes MIME types and splits the
  values of a header
- `impl.labels`, the labels of the Encoding Standard
- `impl.decoding`, the decoders behind `mime/decode`
- `impl.bytes`, the bytes on each platform
- `impl.media`, the signatures of MP4, WebM and MP3
- `impl.feed`, the rules for feeds that the standard dropped

License
-------

The whatwg-mime project is licensed under the [MIT licence](LICENSE).
