#!/bin/sh
# Download the test data of web-platform-tests and the labels of the
# Encoding Standard, at the versions that the library follows, into
# dev-resources/.
set -eu

wpt=c7bbc237dc396576b7486224a40a2ae2fa6d1141
encoding=a985b62a9b45c17da3e17a9f0a0b4e30c34c4a8a

cd "$(dirname "$0")/.."
mkdir -p dev-resources/wpt/media dev-resources/wpt/sniffing dev-resources/encoding

base="https://raw.githubusercontent.com/web-platform-tests/wpt/$wpt"

for f in mimesniff/mime-types/resources/mime-types.json \
         mimesniff/mime-types/resources/generated-mime-types.json \
         mimesniff/mime-types/resources/mime-groups.json \
         fetch/content-type/resources/content-types.json \
         fetch/content-type/resources/script-content-types.json \
         fetch/nosniff/resources/x-content-type-options.json; do
  curl -sSfL -o "dev-resources/wpt/$(basename "$f")" "$base/$f"
done

for f in mp3-raw.mp3 mp3-with-id3.mp3 flac.flac ogg.ogg mp4.mp4 wav.wav webm.webm; do
  curl -sSfL -o "dev-resources/wpt/media/$f" "$base/mimesniff/media/resources/$f"
done

for f in binary-data.bin png-image.png test-file.zip html-content.html; do
  for g in "$f" "$f.headers"; do
    curl -sSfL -o "dev-resources/wpt/sniffing/$g" "$base/mimesniff/sniffing/resources/$g"
  done
done

curl -sSfL -o dev-resources/encoding/encodings.json \
  "https://raw.githubusercontent.com/whatwg/encoding/$encoding/encodings.json"
