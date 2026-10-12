whatwg-mime: a proposal
=======================

A Clojure(Script) library of the
[MIME Sniffing Standard](https://mimesniff.spec.whatwg.org/) (of 17 July
2026) and the Content-Type rules of the
[Fetch Standard](https://fetch.spec.whatwg.org/) (of 6 October 2026), as
`dk.simongray/whatwg-mime`. It reads a Content-Type the way a browser does
and tells what a resource is from its first bytes. It follows whatwg-url:
one cljc codebase that needs only Clojure 1.11 and Java 11, plain data,
the spec's sections cited in the code and web-platform-tests as the test
suite.

Two findings change the brief:

- **The standard no longer sniffs feeds.** It dropped its rules for a feed
  mislabelled as HTML on 15 July 2024 (whatwg/mimesniff commit b47be44),
  because no browser reads a text/html resource that starts with `<rss`
  as a feed. Since websub-clj needs those rules and podcast-clj already
  copies them, the library carries them all the same (as
  `sniff/feed-type`, apart from `mime/sniff`).
- **No native code is worth using.** Only Node has a parser of the
  standard. No platform exposes its sniffing.


Scope
-----

From the MIME Sniffing Standard:

- MIME types: parsing, serialising, the valid MIME type string and the
  groups (§4.1 to §4.6)
- the supplied MIME type with its check for the old Apache bug, and the
  resource header of 1445 bytes (§5)
- pattern matching and all four tables of patterns, with the MP4, WebM
  and MP3 signatures (§6)
- the computed MIME type, the rules for an unknown type and the rules
  that tell text from binary (§7)
- the browsing context (§8.1), which is the algorithm of §7

From the version of the standard before 15 July 2024: the rules for a
mislabelled feed (§7.3 then).

From Fetch: collecting a quoted string and "get, decode, and split"
(§2.2), "extract a MIME type" and "legacy extract an encoding" (§3.5),
and "determine nosniff" (§3.6).

From the [Encoding Standard](https://encoding.spec.whatwg.org/) (of 21
May 2026): "get an encoding" and its table of labels (§4.2), which the
legacy extract needs. Decoding stays in wary-fetch.

**Left out:**

- The image, audio or video, and font contexts (§8.2, §8.3, §8.7). None
  of your projects needs them, and each is a few lines over a table of
  the `sniff` namespace. An option for them can come later without
  breaking anyone.
- The plugin, style, script, text track and cache manifest contexts. They
  never read the bytes: two are unfinished in the standard, two return a
  constant and plugins are gone.
- "Minimize a supported MIME type" (§4.2), which needs to know what the
  browser can render.
- The JavaScript essence match, a hook for HTML's script element. The
  `javascript?` predicate covers a parsed type.
- Parsing from bytes and serialising to bytes. Header values are already
  strings on every platform.
- Reading the resource header from a stream. The caller has the bytes.
  The library reads at most the first 1445.
- Fetch's check that blocks a response for nosniff, which needs the
  destination of a browser's request.

**Two readings of the standard:**

- **Every type counts as supported.** Section 7 sniffs an image or media
  type only when the browser supports it. A library renders nothing, so
  sniffing every image or media type only makes the answer more exact.
- **The supplied type comes from Fetch.** Section 5.1 takes the last
  Content-Type as it is, but browsers use Fetch's "extract a MIME type".
  WPT expects a page served with text/html and then `*/*` to be HTML,
  where §5.1 would drop the text/html. The Apache check still compares
  the text of the last value exactly.


API
---

The root namespace holds the MIME types and the call that sniffs:

```clojure
(require '[dk.simongray.whatwg-mime :as mime])

(mime/parse "Text/HTML; Charset=\"utf-8\"; x=(")
;; => {:type "text" :subtype "html" :parameters {"charset" "utf-8" "x" "("}}

(mime/serialize "Text/HTML; Charset=\"utf-8\"; x=(")
;; => "text/html;charset=utf-8;x=\"(\""

(mime/extract ["text/html;charset=gbk;a=b" "text/html;x=y"])
;; => {:type "text" :subtype "html" :parameters {"x" "y" "charset" "gbk"}}

(mime/charset "text/html; x=\"charset=evil\"; charset=utf-8")
;; => "utf-8"

(mime/encoding "text/html; charset=latin1")
;; => "windows-1252"

(mime/audio-or-video? "application/ogg")
;; => true
```

A MIME type is a map of its :type and :subtype in lower case, with
:parameters only when it has any. The parameters map lower-case names to
values in the order of the input, so `serialize` writes them back in that
order. Every function that takes a MIME type also takes its text and
parses it first, as whatwg-url does with URLs.

A parse keeps that order whatever the number of parameters, but an assoc
of a ninth turns the map into a hash map with an order of its own. So
every function that reads the parameters also takes a vector of
name-value pairs, which costs about nothing since both read as a seq of
pairs. To put a ninth parameter in a set place, build the vector. An
ordered map would need a dependency or a map type of the library's own,
for an order that only shows in a serialisation.

- MIME types (§4): `parse`, `serialize`, `essence`, `charset` and `valid?`
- The groups (§4.6): `image?`, `audio-or-video?`, `font?`, `zip-based?`,
  `archive?`, `xml?`, `html?`, `scriptable?`, `javascript?` and `json?`
- Content-Type (Fetch §3.5): `extract`, which takes the values as a
  string or a seq of strings, and `encoding`, the name of the encoding
  that a type's charset label stands for
- X-Content-Type-Options (Fetch §3.6): `nosniff?`, which takes the values
  the same way
- Sniffing (§7): `sniff`, which gives the computed MIME type of the
  bytes and the supplied Content-Type (the values, a parsed type or nil)

The bytes are a byte array on the JVM and a Uint8Array in ClojureScript (a
Node Buffer is one). The library reads at most their first 1445 bytes, so
you can pass a whole body. For the bytes `page` of an HTML page served
without a type, and `feed` of an RSS feed served as text/html:

```clojure
(require '[dk.simongray.whatwg-mime.sniff :as sniff])

(mime/sniff page nil)
;; => {:type "text" :subtype "html"}

(mime/sniff feed "text/html")
;; => {:type "text" :subtype "html"}

(sniff/feed-type feed)
;; => "application/rss+xml"
```

A browser shows the feed as a page, since the standard no longer sniffs
feeds. The only option of `sniff` is :no-sniff?, which `nosniff?`
answers, just as `href` in whatwg-url takes only :fragment?.

The `sniff` namespace holds the parts of the algorithm, for callers who
know what they're looking for:

- `resource-header-length`, the 1445 bytes (§5.2)
- `matches?`, the pattern matching algorithm (§6)
- `image-type`, `audio-or-video-type`, `font-type` and `archive-type`,
  which return the type of the first row that matches, e.g. "audio/mpeg",
  or nil (§6.1 to §6.4)
- `unknown-type` and `text-or-binary` (§7.1, §7.2)
- `feed-type`, the old rules for a mislabelled feed, which return
  application/rss+xml, application/atom+xml or nil
- each table of patterns as data

The other contexts that read bytes take a table's answer, or else the
supplied type unless it's XML. For an image element:

```clojure
(if (mime/xml? content-type)
  content-type
  (or (sniff/image-type b) content-type))
```

The internal namespaces are `impl.parser` (parsing, serialising, quoted
strings and the header values of Fetch), `impl.media` (the MP4, WebM and
MP3 signatures, step by step) and `impl.bytes` (a byte of an array on each
platform, and the scan for binary bytes).


Errors and validation
---------------------

Unlike the URL Standard, the MIME Sniffing Standard names no validation
errors. A parse fails, or it drops a parameter without a word. So there's
no `validation-errors`. Instead `valid?` checks the valid MIME type string
of §4.3 (HTTP's media-type grammar), for checkers such as podcast-clj's
feed validator. Names for the reasons would be the library's own, not the
standard's.

No function throws. A failed parse or extract is nil, as is the encoding
of an unknown label or a table that matches nothing. A sniff always
returns a type.


Native code
-----------

- **JVM:** Nothing. The JDK has no parser of the standard. Its own
  sniffer (`URLConnection/guessContentTypeFromStream`) follows other
  rules: it reads a WebP header as audio/x-wav and `<?xml` as
  application/xml. It has no rule for MP3, Ogg or PDF.
- **Node:** The `util.MIMEType` class implements the standard's parser
  and serialiser. It has been stable since Node 22.15 and passes all 955
  parsing cases of WPT.
- **Browser:** No parser that you can call. Fetch's extract shows only as
  the type of a response's blob (behind a promise). Sniffing stays inside
  the engine.

So the library can't lean on the platform as whatwg-url does: nothing
exists on all three, and the parser is short. The only platform code reads
a byte (a signed one on the JVM). Node's `util.MIMEType` still serves the
generative tests in Node as an oracle.


Tests
-----

As in whatwg-url, the script `dev/fetch.sh` downloads the WPT files at a
pinned commit into `dev-resources/`, which Git ignores. Today's WPT commit
c7bbc237 has everything below.

| WPT file | Tests |
|---|---|
| `mimesniff/mime-types/resources/mime-types.json` and `generated-mime-types.json` | `parse`, `serialize` and `encoding` |
| `mimesniff/mime-types/resources/mime-groups.json` | the group predicates |
| `fetch/content-type/resources/content-types.json` | `extract` and `encoding`, with the values both joined and separate |
| `fetch/content-type/resources/script-content-types.json` | `extract`, `javascript?` and `encoding` |
| `fetch/nosniff/resources/x-content-type-options.json` | `nosniff?` |
| `mimesniff/media/resources/` and `mimesniff/sniffing/resources/` | `sniff` |

The script also downloads the Encoding Standard's `encodings.json`, and a
test checks the library's table of labels against it. The parsing data
also says whether a browser would display the type, which belongs to HTML
and is skipped. Two cases of the groups still say application/font-off,
which the standard corrected to application/font-otf in July 2025
(whatwg/mimesniff#165). The test follows the standard.

The binary files are WPT's own: MP3 with and without ID3, MP4, WebM, Ogg,
WAV and FLAC, plus a ZIP, a PNG, a gzip file and an HTML page that WPT
serves as text/plain. WPT checks them in a browser, so the expected types
are written in the test from the spec (e.g. FLAC matches no pattern).

Sniffing has no data suite beyond these, so the rest comes from the spec:

- **Its tables, written out by hand.** Each row of the patterns gets an
  input from its note in the spec and some near misses: leading whitespace
  where the row allows it and where it doesn't, other cases of a letter
  under the case-insensitive mask, no tag-terminating byte, one byte too
  few. They're written by hand rather than generated, so that a typo in a
  table of the code fails a test.
- **The steps of §7**, with a case for each. XML and HTML stay as
  supplied, and the three unknown types get sniffed. With nosniff, a known
  type stays as supplied. The four Apache strings match exactly, while
  text/plain;charset=UTF-8 without the space doesn't.
- **Generative tests** of what the standard promises. A parsed type
  serialises and parses back to itself, and the serialisation is always a
  valid MIME type string. The rules for text or binary never give a
  scriptable type, as §7.2 requires. Bytes after the first 1445 never
  change a result. In Node, `parse` and `serialize` agree with
  `util.MIMEType` on random strings.

**The spec's media signatures have open bugs.** As written, the MP3 rules
take the first frame of WPT's mp3-raw.mp3 for about 130 bytes when it's
208. Their step 7 also compares against s − length, which rejects every
file (whatwg/mimesniff#70, #168). The WebM steps read the size of an
element from the start of the file rather than from the element (#146,
#167). The library implements what the steps evidently mean and cites the
issue beside each departure. WPT's media files check the result. A TODO
beside each departure says to offer the fix on the issue once those files
pass, and to make a pull request only if an editor asks for one.


Performance
-----------

Parsing a Content-Type or sniffing 1445 bytes should take microseconds, so
the work is narrow. A cljc bench like whatwg-url's times `parse` and
`extract` of typical headers, and `sniff` of an HTML page, a PNG, an MP3
file and a body of text served with one of the Apache types. The likely
hot spots are the pattern loop and the scan for binary bytes. Each runs
over the byte array in a primitive loop, split into named steps such as
skipping the ignored bytes and comparing under the mask. The tables become
byte arrays when the namespace loads. An optimisation stays only when
criterium shows that it matters, with a comment that says so.


Adoption
--------

**In wary-fetch,** the Content-Type comes out right on every platform:

- Version 0.5.0 removes `headers/media-type` and `headers/charset`. Their
  callers move to whatwg-mime in the same round of releases, as they did
  for whatwg-url. Wrappers would fix less than they seem, because each
  Content-Type call site passes `media-type` the first value.
- The facts read the type with `mime/extract`, which takes the last valid
  value. In a browser, fetch joins two Content-Types into "text/plain,
  text/html", and `media-type` currently returns that whole.
- Decoding takes its encoding from `mime/encoding`, so a charset inside a
  quoted parameter (as in `x="charset=evil"`) no longer counts. On the
  JVM, a feed labelled iso-8859-1 then decodes as windows-1252, as it
  does in Node and browsers: its curly quotes no longer turn into control
  characters. Most of the standard's names are Java charsets too, but
  macintosh is x-MacRoman, and the JDK lacks a few (e.g. ISO-8859-10 and
  x-user-defined).
- The proxy's `text-type?` gives way to `mime/json?`, `mime/xml?` and
  `mime/javascript?` beside the text type. The rewritten Content-Type
  keeps its other parameters with
  `(mime/serialize (assoc-in m [:parameters "charset"] "utf-8"))`.
- Like a browser's fetch, wary-fetch doesn't sniff. Sniffing depends on
  the context, so it's left to the caller.

**In websub-clj,** `document/kind` swaps its own rules for an unknown type
for `mime/sniff`, on the body before it's decoded:

```clojure
(defn kind
  "The kind of the document in the bytes `b` served with `content-type`,
  :html or :xml, or nil for another."
  [b content-type]
  (let [computed (mime/sniff b content-type)]
    (cond
      (sniff/feed-type b)
      :xml

      (#{"text/html" "application/xhtml+xml"} (mime/essence computed))
      :html

      (mime/xml? computed)
      :xml)))
```

The regexes of `kind` go. A feed served as text/html or text/plain gives
up its atom:link hubs. A page served without a type that starts with
`<head>` or a comment reads as HTML, where it now goes to the XML parser.

**In podcast-clj,** the library replaces the checks of types and feeds
but not the media sniffing:

- In feed/validate.cljc, `mime/valid?` replaces `media-type-pattern` and
  `media-type?`. The `playable-type?` check keeps only its playlists
  beside `mime/audio-or-video?`, so an enclosure of type application/ogg
  no longer draws :validate/unknown-media-type.
- In feed/discovery.cljc, `feed-document?` and `first-element` copy the
  removed feed rules, so they go. They look 4 KB into a page where the
  old rules look at 1445 bytes. Since `sniff/feed-type` takes bytes,
  discovery would encode the start of the body first.
- The `format.media/sniff` function stays. Its job is to choose a
  parser, so it's looser on purpose: it accepts any ftyp box, since an
  M4A file may name no mp4 brand (whatwg/mimesniff#149), and one MPEG
  frame where the standard wants two. The `format.transcript/sniff`
  function stays too, since the standard doesn't cover its formats.
- To say what a mislabelled enclosure is, the check can read every
  enclosure whatever its declared type. The `media/read!` function returns
  the :format of an MP3 or MP4 file anyway.
- The `headers/media-type` calls on type attributes become `mime/essence`.

**In indieauth-clj, webmention-clj and relmeauth-clj,** each check of a
response reads the first Content-Type with `headers/media-type` and
`headers/header`. It becomes
`(mime/essence (mime/extract (get headers "content-type")))`. These
libraries count application/xhtml+xml as HTML where the standard counts
it as XML, so they keep their sets. The JSON regex of webmention-clj
becomes `mime/json?`.

**In html-pieces,** there's no MIME code to replace. Its `markup?` judges
a text, not a resource.


Size
----

About 1000 lines of source with the feed rules and the table of labels
(whatwg-url has about 3000). That's a 2 on the ranking's scale for the
code, and nearer 3 with the media bugs, the README, CI and the bench.
