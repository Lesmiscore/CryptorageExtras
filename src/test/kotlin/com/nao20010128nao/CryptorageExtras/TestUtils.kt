package com.nao20010128nao.CryptorageExtras

import com.google.common.io.ByteSink
import com.google.common.io.ByteSource
import com.nao20010128nao.Cryptorage.Cryptorage
import com.nao20010128nao.Cryptorage.FileSource
import com.nao20010128nao.Cryptorage.newMemoryFileSource
import com.nao20010128nao.Cryptorage.withV1Encryption

val zeroBytes = byteArrayOf()

fun FileSource.fakeWrap(): Cryptorage {
    return object : Cryptorage {
        override val isReadOnly: Boolean
            get() = this@fakeWrap.isReadOnly

        override fun close() {
            this@fakeWrap.close()
        }

        override fun commit() {
            this@fakeWrap.commit()
        }

        override fun delete(name: String) {
            this@fakeWrap.delete(name)
        }

        override fun gc() = Unit
        override fun lastModified(name: String): Long = this@fakeWrap.lastModified(name)
        override fun list(): List<String> = this@fakeWrap.list()
        override fun meta(key: String): String? = null
        override fun meta(key: String, value: String) = Unit
        override fun mv(from: String, to: String) = Unit
        override fun open(name: String, offset: Int): ByteSource = this@fakeWrap.open(name, offset)
        override fun put(name: String): ByteSink = this@fakeWrap.put(name)
        override fun size(name: String): Long = this@fakeWrap.size(name)
    }
}

fun Map<String, ByteArray>.createV1(): Cryptorage {
    val ms = emptyMap<String, ByteArray>().newMemoryFileSource()
    val v1 = ms.withV1Encryption("test")
    v1.meta(Cryptorage.META_SPLIT_SIZE, "200")
    for ((k, v) in this) {
        v1.put(k).write(v)
    }
    v1.commit()
    return v1
}