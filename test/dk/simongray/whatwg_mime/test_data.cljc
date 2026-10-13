(ns dk.simongray.whatwg-mime.test-data
  "The files that dev/fetch.sh puts in dev-resources, read the same way on
  the JVM and in Node. Each is nil when it isn't there, and the tests of
  its data then check nothing."
  (:refer-clojure :exclude [bytes])
  (:require #?(:cljs ["fs" :as fs])
            #?(:clj [clojure.data.json :as json])
            #?(:clj [clojure.java.io :as io])))

(defn- found
  "The path of the file at `path` in dev-resources, or nil when it isn't
  there."
  [path]
  (let [path (str "dev-resources/" path)]
    (when #?(:clj (.exists (io/file path)) :cljs (fs/existsSync path))
      path)))

(defn text
  "The text of the file at `path` in dev-resources, or nil."
  [path]
  (when-let [path (found path)]
    #?(:clj  (slurp path)
       :cljs (fs/readFileSync path "utf8"))))

(defn json
  "The data of the JSON file at `path` in dev-resources, with string keys,
  or nil."
  [path]
  (when-let [s (text path)]
    #?(:clj  (json/read-str s)
       :cljs (js->clj (js/JSON.parse s)))))

(defn bytes
  "The bytes of the file at `path` in dev-resources, as the platform keeps
  them, or nil."
  [path]
  (when-let [path (found path)]
    #?(:clj  (java.nio.file.Files/readAllBytes (.toPath (io/file path)))
       :cljs (fs/readFileSync path))))
