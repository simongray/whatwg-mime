(ns dk.simongray.whatwg-mime.octets
  "Bytes for the tests, as the platform keeps them: a byte array on the
  JVM and a Uint8Array in JavaScript.")

(defn- codes
  "The bytes of the `part`: the code units of a text of Latin-1, or a
  number, or the numbers of a seq."
  [part]
  (cond
    (string? part) (map #?(:clj int :cljs #(.charCodeAt % 0)) part)
    (number? part) [part]
    :else          part))

(defn octets
  "The bytes of the `parts`, each a text of Latin-1, a byte or a seq of
  bytes.

      (octets \"GIF89a\" 0 [1 2])"
  [& parts]
  (let [xs (mapcat codes parts)]
    #?(:clj  (byte-array (map unchecked-byte xs))
       :cljs (js/Uint8Array.from (clj->js xs)))))
