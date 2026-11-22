package com.voria.umsh.services.mobilecore

/**
 * The app's own log lines. `UmshApplication` points [sink] at logcat; until
 * then, and in the JVM tests, lines go to standard error.
 */
object AppLog {
    enum class Level { Error, Warn, Info, Debug }

    fun interface Sink {
        fun write(level: Level, tag: String, message: String)
    }

    @Volatile
    var sink: Sink = Sink { level, tag, message -> System.err.println("$level $tag: $message") }

    fun e(tag: String, message: String) = sink.write(Level.Error, tag, message)

    fun w(tag: String, message: String) = sink.write(Level.Warn, tag, message)

    fun i(tag: String, message: String) = sink.write(Level.Info, tag, message)

    fun d(tag: String, message: String) = sink.write(Level.Debug, tag, message)
}
