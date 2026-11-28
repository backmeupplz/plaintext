package com.borodutch.plaintext

import android.content.Context
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
import android.print.PrintManager
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.plaintext_ffi.deviceCode
import java.io.FileOutputStream
import java.io.OutputStream
import java.text.DateFormat
import java.util.Date

/**
 * The printable Emergency Kit: Secret Key, server, username, a blank line for the password, and the sign-in QR
 * for a new device. It's drawn straight into the file the person picked or the print job, never a temp file.
 */
object EmergencyKit {
    private fun write(out: OutputStream, secretKey: String, server: String, username: String) {
        val doc = PdfDocument()
        val page = doc.startPage(PdfDocument.PageInfo.Builder(612, 792, 1).create())
        val c = page.canvas
        val green = 0xFF1F7A4D.toInt()
        val gray = 0xFF66665F.toInt()
        val mono = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        fun paint(size: Float, color: Int = 0xFF000000.toInt(), face: Typeface = Typeface.DEFAULT) =
            TextPaint(Paint.ANTI_ALIAS_FLAG).apply { textSize = size; this.color = color; typeface = face }
        fun para(text: String, p: TextPaint, x: Float, y: Float, width: Int): Float {
            val l = StaticLayout.Builder.obtain(text, 0, text.length, p, width).setAlignment(Layout.Alignment.ALIGN_NORMAL).build()
            c.save(); c.translate(x, y); l.draw(c); c.restore()
            return y + l.height
        }
        val left = 48f
        val width = 612 - 96
        var y = 72f
        val word = paint(30f, face = mono)
        c.drawText("plain", left, y, word)
        c.drawText("text", left + word.measureText("plain"), y, word.apply { color = green })
        val title = paint(20f, face = Typeface.create(Typeface.DEFAULT, Typeface.BOLD))
        c.drawText("Emergency Kit", 612 - 48 - title.measureText("Emergency Kit"), y, title)
        y += 26
        y = para("Created for $username on ${DateFormat.getDateInstance(DateFormat.LONG).format(Date())}.", paint(12f, gray), left, y, width) + 14
        y = para(
            "Your Secret Key and your password together open your account. Nobody can recover them for you, not even whoever runs your server. Keep this page somewhere safe, like with your passport.",
            paint(13f), left, y, width,
        ) + 20
        val label = paint(10f, gray, Typeface.create(Typeface.DEFAULT, Typeface.BOLD))
        fun row(name: String, value: String) {
            c.drawText(name, left, y + 10, label)
            y = para(value, paint(15f, face = Typeface.MONOSPACE), left, y + 16, width) + 18
        }
        row("SERVER", server)
        row("USERNAME", username)
        c.drawText("SECRET KEY", left, y + 10, label)
        val keyPaint = paint(19f, face = mono)
        val keyLayout = StaticLayout.Builder.obtain(secretKey, 0, secretKey.length, keyPaint, width - 24).build()
        c.drawRect(RectF(left, y + 18, left + width, y + 18 + keyLayout.height + 24), Paint().apply { color = 0xFFEFEEE7.toInt() })
        c.save(); c.translate(left + 12, y + 30); keyLayout.draw(c); c.restore()
        y += 18 + keyLayout.height + 24 + 24
        c.drawText("PASSWORD", left, y + 10, label)
        c.drawLine(left, y + 50, left + width, y + 50, Paint().apply { strokeWidth = 1f })
        y = para("Write it here, by hand, only if you keep this page locked away.", paint(10f, gray), left, y + 56, width) + 28
        val qr = qrBitmap(deviceCode(server, username, secretKey))
        c.drawBitmap(qr, Rect(0, 0, qr.width, qr.height), RectF(left, y, left + 130, y + 130), Paint().apply { isFilterBitmap = false })
        val tx = left + 148
        val ty = para("Sign in on a new device", paint(13f, face = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)), tx, y, width - 148) + 6
        para("Choose Sign in, then Scan from another device, and scan this code. It holds your server, username and Secret Key, but not your password.", paint(12f), tx, ty, width - 148)
        doc.finishPage(page)
        doc.writeTo(out)
        doc.close()
    }

    suspend fun save(context: Context, uri: Uri, secretKey: String, server: String, username: String) = withContext(Dispatchers.IO) {
        context.contentResolver.openOutputStream(uri, "wt")?.use { write(it, secretKey, server, username) }
    }

    fun print(context: Context, secretKey: String, server: String, username: String) {
        val pm = context.getSystemService(PrintManager::class.java)
        context.model.external = true
        pm.print("Plaintext Emergency Kit", object : PrintDocumentAdapter() {
            override fun onLayout(old: PrintAttributes?, new: PrintAttributes, cancel: CancellationSignal, cb: LayoutResultCallback, extras: Bundle?) {
                if (cancel.isCanceled) return cb.onLayoutCancelled()
                cb.onLayoutFinished(PrintDocumentInfo.Builder("Plaintext Emergency Kit.pdf").setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT).setPageCount(1).build(), true)
            }

            override fun onWrite(pages: Array<out PageRange>, fd: ParcelFileDescriptor, cancel: CancellationSignal, cb: WriteResultCallback) {
                try {
                    FileOutputStream(fd.fileDescriptor).use { write(it, secretKey, server, username) }
                    cb.onWriteFinished(arrayOf(PageRange.ALL_PAGES))
                } catch (e: Exception) {
                    cb.onWriteFailed(null)
                }
            }
        }, null)
    }
}
