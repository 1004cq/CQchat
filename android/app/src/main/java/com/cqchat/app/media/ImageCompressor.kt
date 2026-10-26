package com.cqchat.app.media

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.cqchat.app.protocol.CQ
import java.io.ByteArrayOutputStream
import kotlin.math.max

object ImageCompressor {
    fun compress(jpegOrPng: ByteArray): Pair<ByteArray, ByteArray>? {
        val bmp = BitmapFactory.decodeByteArray(jpegOrPng, 0, jpegOrPng.size) ?: return null
        val full = resize(bmp, CQ.IMAGE_MAX_EDGE)
        val thumb = resize(bmp, 160)
        return jpeg(full, CQ.IMAGE_JPEG_QUALITY) to jpeg(thumb, 60)
    }

    private fun resize(src: Bitmap, maxEdge: Int): Bitmap {
        val longest = max(src.width, src.height)
        if (longest <= maxEdge) return src
        val scale = maxEdge.toFloat() / longest
        val w = (src.width * scale).toInt().coerceAtLeast(1)
        val h = (src.height * scale).toInt().coerceAtLeast(1)
        return Bitmap.createScaledBitmap(src, w, h, true)
    }

    private fun jpeg(bmp: Bitmap, quality: Int): ByteArray {
        val out = ByteArrayOutputStream()
        bmp.compress(Bitmap.CompressFormat.JPEG, quality, out)
        return out.toByteArray()
    }
}
