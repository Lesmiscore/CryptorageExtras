@file:Suppress("unused")

package com.nao20010128nao.CryptorageExtras.indexer

import com.beust.klaxon.JsonArray
import com.beust.klaxon.JsonObject
import com.google.common.collect.HashMultimap
import com.google.common.io.ByteSource
import com.nao20010128nao.Cryptorage.AesKeys
import com.nao20010128nao.Cryptorage.FileSource
import com.nao20010128nao.Cryptorage.asFileSource
import com.nao20010128nao.Cryptorage.asZipFileSource
import com.nao20010128nao.CryptorageExtras.*
import com.nao20010128nao.CryptorageExtras.bfilter.BloomFilter
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.net.URL
import kotlin.math.max

interface Indexer<T : Indexer<T>> {
    fun addIndex(url: URL)
    fun addIndexDirectory(file: File)
    fun addIndexZip(file: File)
    fun addIndexed(url: URL)
    fun addIndexed(file: File)
    fun list(): List<String>
    fun mv(from: String, to: String)
    fun copy(from: String, to: String)
    fun delete(name: String)
    fun has(name: String): Boolean = list().contains(name)
    fun lastModified(name: String): Long
    fun size(name: String): Long
    fun joinSplits()
    fun merge(indexer: T)

    fun serialize(): ByteSource
    fun bloomFilter(): ByteArray
    fun writeTo(fs: FileSource)
    fun writeTree(fs: FileSource, clean: Boolean = true)
}

class V1Indexer(private val keys: AesKeys) : Indexer<V1Indexer> {

    constructor(password: String) : this(populateKeys(password))

    private val finalIndex: Index = Index()

    override fun addIndex(url: URL) {
        val fs = url.asFileSource()
        val index = readIndex(fs)
        index.files.forEach { (name, file) ->
            finalIndex.files[name] = file.copy(files = file.files.map {
                URL(
                    url.protocol,
                    url.host,
                    url.port,
                    "${url.path}/$it${if (url.query.isNullOrBlank()) "" else "?${url.query}"}"
                ).toString()
            }.toMutableList())
        }
    }

    override fun addIndexDirectory(file: File) {
        val fs = file.asFileSource()
        val index = readIndex(fs)
        index.files.forEach { (name, ff) ->
            finalIndex.files[name] = ff.copy(files = ff.files.map { File(file, name).toString() }.toMutableList())
        }
    }

    override fun addIndexZip(file: File) {
        val fs = file.asZipFileSource()
        val index = readIndex(fs)
        index.files.forEach { (name, ff) ->
            finalIndex.files[name] = ff.copy(files = ff.files.map { "zip:$file!$name" }.toMutableList())
        }
    }

    override fun addIndexed(url: URL) {
        val fs = url.asFileSource()
        val index = readIndex(fs, MANIFEST_INDEX)
        finalIndex.files.putAll(index.files)
    }

    override fun addIndexed(file: File) {
        val fs = file.asFileSource()
        val index = readIndex(fs, MANIFEST_INDEX)
        finalIndex.files.putAll(index.files)
    }


    override fun list(): List<String> = finalIndex.files.keys.toList()

    override fun mv(from: String, to: String) {
        finalIndex.files[to] = finalIndex.files[from]!!
        finalIndex.files.remove(from)
    }

    override fun copy(from: String, to: String) {
        finalIndex.files[to] = finalIndex.files[from]!!
    }

    override fun delete(name: String) {
        finalIndex.files.remove(name)
    }

    override fun joinSplits() {
        val foundSplits = HashMultimap.create<String, String>()
        for (it in list()) {
            val match = splitFilename.matchEntire(it) ?: continue
            val (split, baseName) = match.groupValues
            foundSplits.put(baseName, split)
        }
        foundSplits.asMap().forEach { (name, unsortedPieces) ->
            val pieces = unsortedPieces.sorted()
            // enumerate all consisting file
            val allFiles = pieces.asSequence().flatMap { finalIndex.files[it]!!.files }
            // calculate total size of all files
            val size = pieces.asSequence().map { size(it) }.fold(0L, Long::plus)
            // build a new file
            val newFile = finalIndex.files[pieces[0]]!!.copy(
                files = allFiles.toMutableList(),
                size = size
            )
            // remove old files
            pieces.forEach(this@V1Indexer::delete)
            // add new file
            finalIndex.files[name] = newFile
        }
    }

    override fun lastModified(name: String): Long = finalIndex.files[name]?.lastModified ?: -1

    override fun size(name: String): Long = finalIndex.files[name]?.size ?: -1

    override fun merge(indexer: V1Indexer) {
        finalIndex.files.putAll(indexer.finalIndex.files)
    }

    override fun serialize(): ByteSource = source {
        val root = JsonObject()
        root["files"] = finalIndex.files.mapValues { it.value.toJsonMap() }
        // BLOOM_FILTER is unused as of e2aea0
        root["meta"] = mapOf(
            BLOOM_FILTER to bloomFilter().encodeBase64ToString()
        )
        ByteArrayInputStream(root.toJsonString(false).utf8Bytes())
    }.encrypt(keys)

    override fun bloomFilter(): ByteArray {
        val bf = BloomFilter(max(finalIndex.files.size.toLong(), 3))
        finalIndex.files.keys.forEach {
            bf.add(it.utf8Bytes())
        }
        val baos = ByteArrayOutputStream(bf.sizeInBytes().toInt())
        BloomFilter.serialize(baos, bf)
        return baos.toByteArray()
    }

    override fun writeTo(fs: FileSource) {
        fs.put(MANIFEST_INDEX).writeFrom(serialize().openBufferedStream())
    }

    override fun writeTree(fs: FileSource, clean: Boolean) {
        if (clean) {
            val hierarchyFiles = try {
                fs.open(MANIFEST_INDEX_HIERARCHICAL_LIST).openStream().reader().use { reader ->
                    klaxon.parseJsonArray(reader).map { it.toString() }
                }
            } catch (e: Throwable) {
                emptyList<String>()
            }
            hierarchyFiles.forEach {
                wish {
                    fs.delete(it)
                }
            }
        }
        source {
            val root = JsonObject()
            root["files"] = emptyMap<String, Any?>()
            root["meta"] = mapOf<String, Any?>("hierarchical" to "true")
            root["hierarchical"] = "true"
            ByteArrayInputStream(root.toJsonString(false).utf8Bytes())
        }.encrypt(keys).copyTo(fs.put(MANIFEST_INDEX))

        val files = list().sorted()
        val filesPerLeaf = 10

        data class TreeNode(val name: String, val start: String, val end: String)

        val leaves = files.chunked(filesPerLeaf)
        val dataToWrite = mutableMapOf<String, String>()
        val previousLayer = mutableListOf<TreeNode>()
        var deepness = 1
        // generate leaves
        for ((index, leave) in leaves.withIndex()) {
            dataToWrite["${MANIFEST_INDEX_HIERARCHICAL_LEAF}_${index}"] = JsonObject().also {
                it["files"] = finalIndex.files
                    .filterKeys { it in leave }
                    .also { require(it.size == leave.size) }
                    .mapValues { it.value.toJsonMap() }
                it["type"] = "leaf"
            }.toJsonString()
            previousLayer += TreeNode("${MANIFEST_INDEX_HIERARCHICAL_LEAF}_${index}", leave.first(), leave.last())
        }
        // generate nodes
        while (previousLayer.size > 1) {
            val nodes = previousLayer.chunked(filesPerLeaf)
            previousLayer.clear()
            deepness++
            for ((index, node) in nodes.withIndex()) {
                val fname = "${MANIFEST_INDEX_HIERARCHICAL_NODE}_${deepness}_${index}"
                dataToWrite[fname] = JsonObject().also {
                    it["start"] = node.first().start
                    it["end"] = node.last().end
                    it["child"] = node.map { it.name }
                    it["child_start"] = node.map { it.start }
                    it["type"] = "node"
                }.toJsonString()
                previousLayer += TreeNode(fname, node.first().start, node.last().end)
            }
        }
        require(previousLayer[0].start == files.first())
        require(previousLayer[0].end == files.last())
        dataToWrite[MANIFEST_INDEX_HIERARCHICAL_ROOT] = dataToWrite[previousLayer[0].name]!!
        dataToWrite.remove(previousLayer[0].name)

        // generate list
        dataToWrite[MANIFEST_INDEX_HIERARCHICAL_LIST] = JsonArray(dataToWrite.keys).toJsonString(false)

        // write all nodes
        for ((name, data) in dataToWrite) {
            source { ByteArrayInputStream(data.utf8Bytes()) }
                .encrypt(keys).copyTo(fs.put(name))
        }
    }

    companion object {
        const val MANIFEST: String = "manifest"
        const val MANIFEST_INDEX: String = "manifest_index"
        const val BLOOM_FILTER: String = "bloom_filter"

        const val MANIFEST_INDEX_HIERARCHICAL_LIST: String = "manifest_hierarchical_list"
        const val MANIFEST_INDEX_HIERARCHICAL_ROOT: String = "manifest_hierarchical_root"
        const val MANIFEST_INDEX_HIERARCHICAL_NODE: String = "manifest_hierarchical_node"
        const val MANIFEST_INDEX_HIERARCHICAL_LEAF: String = "manifest_hierarchical_leaf"

        private fun populateKeys(password: String): AesKeys {
            val utf8Bytes1 = password.utf8Bytes()
            val utf8Bytes2 = "$password$password".utf8Bytes()
            return utf8Bytes1.digest().digest().leading(16) to utf8Bytes2.digest().digest().trailing(16)
        }
    }

    private fun readIndex(source: FileSource, manifestName: String = MANIFEST): Index = if (source.has(manifestName)) {
        val data = parseJson(AesDecryptorByteSource(source.open(manifestName), keys).asCharSource().openStream())
        val files = data.obj("files")!!.mapValues { CryptorageFile(it.value as JsonObject) }
        Index(files.toMutableMap())
    } else {
        Index(hashMapOf())
    }

    private data class Index(val files: MutableMap<String, CryptorageFile> = mutableMapOf())

    private data class CryptorageFile(
        val files: MutableList<String> = ArrayList(),
        val splitSize: Int = 0,
        var lastModified: Long = 0,
        var size: Long = 0
    ) {
        constructor(file: JsonObject) : this(
            file.array<String>("files")!!.toMutableList(),
            file.int("splitSize")!!,
            file.long("lastModified")!!,
            file.long("size")!!
        )

        fun toJsonMap(): Map<String, Any> = mapOf(
            "files" to files,
            "splitSize" to splitSize,
            "lastModified" to lastModified,
            "size" to size
        )
    }
}


class V3Indexer(private val keys: AesKeys) : Indexer<V3Indexer> {

    constructor(password: String) : this(populateKeys(password))

    private val finalIndex: Index = Index()

    override fun addIndex(url: URL) {
        val fs = url.asFileSource()
        val index = readIndex(fs)
        index.files.forEach { (name, file) ->
            finalIndex.files[name] = file.copy(files = file.files.map {
                URL(
                    url.protocol,
                    url.host,
                    url.port,
                    "${url.path}/$it${if (url.query.isNullOrBlank()) "" else "?${url.query}"}"
                ).toString()
            }.toMutableList())
        }
    }

    override fun addIndexDirectory(file: File) {
        val fs = file.asFileSource()
        val index = readIndex(fs)
        index.files.forEach { (name, ff) ->
            finalIndex.files[name] = ff.copy(files = ff.files.map { File(file, name).toString() }.toMutableList())
        }
    }

    override fun addIndexZip(file: File) {
        val fs = file.asZipFileSource()
        val index = readIndex(fs)
        index.files.forEach { (name, ff) ->
            finalIndex.files[name] = ff.copy(files = ff.files.map { "zip:$file!$name" }.toMutableList())
        }
    }

    override fun addIndexed(url: URL) {
        val fs = url.asFileSource()
        val index = readIndex(fs, MANIFEST_INDEX)
        finalIndex.files.putAll(index.files)
    }

    override fun addIndexed(file: File) {
        val fs = file.asFileSource()
        val index = readIndex(fs, MANIFEST_INDEX)
        finalIndex.files.putAll(index.files)
    }


    override fun list(): List<String> = finalIndex.files.keys.toList()

    override fun mv(from: String, to: String) {
        finalIndex.files[to] = finalIndex.files[from]!!
        finalIndex.files.remove(from)
    }

    override fun copy(from: String, to: String) {
        finalIndex.files[to] = finalIndex.files[from]!!
    }

    override fun delete(name: String) {
        finalIndex.files.remove(name)
    }

    override fun joinSplits() {
        val foundSplits = HashMultimap.create<String, String>()
        for (it in list()) {
            val match = splitFilename.matchEntire(it) ?: continue
            val (split, baseName) = match.groupValues
            foundSplits.put(baseName, split)
        }
        foundSplits.asMap().forEach { (name, unsortedPieces) ->
            val pieces = unsortedPieces.sorted()
            // enumerate all consisting file
            val allFiles = pieces.asSequence().flatMap { finalIndex.files[it]!!.files }
            // enumerate all nonce
            val allNonce = pieces.asSequence().flatMap { finalIndex.files[it]!!.nonce }
            // calculate total size of all files
            val size = pieces.asSequence().map { size(it) }.fold(0L, Long::plus)
            // build a new file
            val newFile = finalIndex.files[pieces[0]]!!.copy(
                files = allFiles.toMutableList(),
                nonce = allNonce.toMutableList(),
                size = size
            )
            // remove old files
            pieces.forEach(this@V3Indexer::delete)
            // add new file
            finalIndex.files[name] = newFile
        }
    }

    override fun lastModified(name: String): Long = finalIndex.files[name]?.lastModified ?: -1

    override fun size(name: String): Long = finalIndex.files[name]?.size ?: -1

    override fun merge(indexer: V3Indexer) {
        finalIndex.files.putAll(indexer.finalIndex.files)
    }

    override fun serialize(): ByteSource = source {
        val root = JsonObject()
        root["files"] = finalIndex.files.mapValues { it.value.toJsonMap() }
        // BLOOM_FILTER is unused as of e2aea0
        root["meta"] = mapOf(
            BLOOM_FILTER to bloomFilter().encodeBase64ToString()
        )
        ByteArrayInputStream(root.toJsonString(false).utf8Bytes())
    }.encrypt(keys)

    override fun bloomFilter(): ByteArray {
        val bf = BloomFilter(max(finalIndex.files.size.toLong(), 3))
        finalIndex.files.keys.forEach {
            bf.add(it.utf8Bytes())
        }
        val baos = ByteArrayOutputStream(bf.sizeInBytes().toInt())
        BloomFilter.serialize(baos, bf)
        return baos.toByteArray()
    }

    override fun writeTo(fs: FileSource) {
        fs.put(MANIFEST_INDEX).writeFrom(serialize().openBufferedStream())
    }

    override fun writeTree(fs: FileSource, clean: Boolean) {
        if (clean) {
            val hierarchyFiles = try {
                fs.open(V1Indexer.MANIFEST_INDEX_HIERARCHICAL_LIST).openStream().reader().use { reader ->
                    klaxon.parseJsonArray(reader).map { it.toString() }
                }
            } catch (e: Throwable) {
                emptyList<String>()
            }
            hierarchyFiles.forEach {
                wish {
                    fs.delete(it)
                }
            }
        }
        source {
            val root = JsonObject()
            root["files"] = emptyMap<String, Any?>()
            root["meta"] = mapOf<String, Any?>("hierarchical" to "true")
            root["hierarchical"] = "true"
            ByteArrayInputStream(root.toJsonString(false).utf8Bytes())
        }.encrypt(keys).copyTo(fs.put(V1Indexer.MANIFEST_INDEX))

        val files = list().sorted()
        val filesPerLeaf = 10

        data class TreeNode(val name: String, val start: String, val end: String)

        val leaves = files.chunked(filesPerLeaf)
        val dataToWrite = mutableMapOf<String, String>()
        val previousLayer = mutableListOf<TreeNode>()
        var deepness = 1
        // generate leaves
        for ((index, leave) in leaves.withIndex()) {
            dataToWrite["${V1Indexer.MANIFEST_INDEX_HIERARCHICAL_LEAF}_${index}"] = JsonObject().also {
                it["files"] = finalIndex.files
                    .filterKeys { it in leave }
                    .also { require(it.size == leave.size) }
                    .mapValues { it.value.toJsonMap() }
                it["type"] = "leaf"
            }.toJsonString()
            previousLayer += TreeNode(
                "${V1Indexer.MANIFEST_INDEX_HIERARCHICAL_LEAF}_${index}",
                leave.first(),
                leave.last()
            )
        }
        // generate nodes
        while (previousLayer.size > 1) {
            val nodes = previousLayer.chunked(filesPerLeaf)
            previousLayer.clear()
            deepness++
            for ((index, node) in nodes.withIndex()) {
                val fname = "${V1Indexer.MANIFEST_INDEX_HIERARCHICAL_NODE}_${deepness}_${index}"
                dataToWrite[fname] = JsonObject().also {
                    it["start"] = node.first().start
                    it["end"] = node.last().end
                    it["child"] = node.map { it.name }
                    it["child_start"] = node.map { it.start }
                    it["type"] = "node"
                }.toJsonString()
                previousLayer += TreeNode(fname, node.first().start, node.last().end)
            }
        }
        require(previousLayer[0].start == files.first())
        require(previousLayer[0].end == files.last())
        dataToWrite[V1Indexer.MANIFEST_INDEX_HIERARCHICAL_ROOT] = dataToWrite[previousLayer[0].name]!!
        dataToWrite.remove(previousLayer[0].name)

        // generate list
        dataToWrite[V1Indexer.MANIFEST_INDEX_HIERARCHICAL_LIST] = JsonArray(dataToWrite.keys).toJsonString(false)

        // write all nodes
        for ((name, data) in dataToWrite) {
            source { ByteArrayInputStream(data.utf8Bytes()) }
                .encrypt(keys).copyTo(fs.put(name))
        }
    }

    companion object {
        const val MANIFEST: String = "manifest"
        const val MANIFEST_NONCE = "manifest_nonce"
        const val MANIFEST_INDEX: String = "manifest_index"
        const val BLOOM_FILTER: String = "bloom_filter"

        private fun populateKeys(password: String): AesKeys {
            val utf8Bytes1 = password.utf8Bytes()
            val utf8Bytes2 = "$password$password".utf8Bytes()
            return utf8Bytes1.digest().digest().leading(16) to utf8Bytes2.digest().digest().trailing(16)
        }
    }

    private fun readIndex(source: FileSource, manifestName: String = MANIFEST): Index = if (source.has(manifestName)) {
        val manifestKeys = if (source.has(MANIFEST_NONCE)) {
            val iv = source.open(MANIFEST_NONCE).read()
            keys.copy(second = iv)
        } else {
            keys
        }
        val data =
            parseJson(AesDecryptorByteSource(source.open(manifestName), manifestKeys).asCharSource().openStream())
        val files = data.obj("files")!!.mapValues { CryptorageFile(it.value as JsonObject) }
        Index(files.toMutableMap())
    } else {
        Index(hashMapOf())
    }

    private data class Index(val files: MutableMap<String, CryptorageFile> = mutableMapOf())

    private data class CryptorageFile(
        val files: MutableList<String> = ArrayList(),
        val nonce: MutableList<BigInteger> = ArrayList(),
        val splitSize: Int = 0,
        var lastModified: Long = 0,
        var size: Long = 0
    ) {
        constructor(file: JsonObject) :
                this(
                    file.array<String>("files")!!.toMutableList(),
                    // allow reading V1 cryptorage (V1 is also acceptable as V3, with all nonce are zero)
                    (file.array<String>("nonce")?.map { it.toBigInteger() }
                        ?: List<BigInteger>(file.array<String>("files")!!.size) { BigInteger.ZERO })
                        .toMutableList(),
                    file.int("splitSize")!!,
                    file.long("lastModified")!!,
                    file.long("size")!!
                )

        fun toJsonMap(): Map<String, Any> = mapOf(
            "files" to files,
            "nonce" to nonce.map { "$it" },
            "splitSize" to splitSize,
            "lastModified" to lastModified,
            "size" to size
        )
    }
}
