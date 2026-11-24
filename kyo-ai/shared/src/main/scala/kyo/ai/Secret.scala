package kyo.ai

import java.nio.charset.StandardCharsets
import kyo.*

/** A provider API key, held as bytes and never rendered.
  *
  * `Config.apiKey` carries one. It is a `final class`, not a case class, so it has no extractor and no
  * `Product` view of its bytes; `toString` prints `Secret(****)`, so a logged `Config` (or any value that
  * holds one: `AIEnv`, `LLM.State`) masks the key. The bytes are read back only by kyo itself, at the
  * moment a completion backend attaches the auth header (`reveal` is `private[kyo]`).
  *
  * Two secrets are equal when their bytes are, compared in constant time; `hashCode` is a constant, so
  * no function of the key escapes through a hash. `wipe` zeroes the held bytes, for a caller that owns
  * the key's lifetime: a wiped secret no longer authenticates.
  *
  * Build one from a `String` with `Secret(value)`, or from bytes with `Secret.fromBytes`, which copies,
  * so a caller that never had the key as a `String` does not have to make one.
  */
final class Secret private (private val bytes: Array[Byte]) derives CanEqual:

    /** The key as the wire needs it. Called only where a completion backend attaches the auth header. */
    private[kyo] def reveal: String = new String(bytes, StandardCharsets.UTF_8)

    /** Zeroes the held bytes. */
    def wipe(using Frame): Unit < Sync = Sync.defer(java.util.Arrays.fill(bytes, 0.toByte))

    override def toString: String = "Secret(****)"

    override def equals(that: Any): Boolean =
        that match
            case other: Secret => Secret.sameBytes(bytes, other.bytes)
            case _             => false

    override def hashCode: Int = Secret.hash

end Secret

object Secret:

    /** Wraps a key held as a `String` (the UTF-8 bytes of `value`). */
    def apply(value: String): Secret = new Secret(value.getBytes(StandardCharsets.UTF_8))

    /** Wraps a copy of `bytes` (the UTF-8 encoding of the key); the caller keeps, and may wipe, its own array. */
    def fromBytes(bytes: Array[Byte]): Secret = new Secret(bytes.clone())

    private val hash: Int = "kyo.ai.Secret".hashCode

    // Constant time in the length of the shorter input: every byte is compared, the result is read once.
    private def sameBytes(a: Array[Byte], b: Array[Byte]): Boolean =
        var diff = a.length ^ b.length
        var i    = 0
        val n    = math.min(a.length, b.length)
        while i < n do
            diff |= a(i) ^ b(i)
            i += 1
        diff == 0
    end sameBytes

end Secret
