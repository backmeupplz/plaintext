package com.borodutch.plaintext

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.util.concurrent.Executors

/** A QR code as a bitmap, one pixel per module (scale it up with nearest-neighbour filtering). */
fun qrBitmap(text: String): Bitmap {
    val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 1))
    val px = IntArray(m.width * m.height) { if (m.get(it % m.width, it / m.width)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
    return Bitmap.createBitmap(px, m.width, m.height, Bitmap.Config.ARGB_8888)
}

@Composable
fun QrImage(text: String, size: Dp, description: String) {
    val img: ImageBitmap = remember(text) { qrBitmap(text).asImageBitmap() }
    Image(
        img, description, filterQuality = FilterQuality.None,
        modifier = Modifier.size(size).clip(RoundedCornerShape(8.dp)).background(Color.White).padding(6.dp),
    )
}

/**
 * The camera, looking for a QR code. [onCode] returns an error to show (and keeps scanning) or null when done.
 * Codes are only ever read here, inside the app, never from links (UI.md; audit findings 2 and 9).
 */
@Composable
fun Scanner(prompt: String, onCode: (String) -> String?) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    var granted by remember { mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) }
    var denied by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it; denied = !it }
    LaunchedEffect(Unit) { if (!granted) { context.model.external = true; ask.launch(Manifest.permission.CAMERA) } }

    Column(Modifier.fillMaxWidth().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(prompt, color = P.muted, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyLarge)
        Box(Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(14.dp)).background(Color.Black).border(1.dp, P.line, RoundedCornerShape(14.dp))) {
            if (granted) {
                val executor = remember { Executors.newSingleThreadExecutor() }
                var done by remember { mutableStateOf(false) }
                DisposableEffect(Unit) { onDispose { executor.shutdown() } }
                AndroidView(
                    modifier = Modifier.fillMaxSize(),
                    factory = { ctx ->
                        val view = PreviewView(ctx)
                        val future = ProcessCameraProvider.getInstance(ctx)
                        future.addListener({
                            val provider = future.get()
                            val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                            val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
                            val reader = QRCodeReader()
                            analysis.setAnalyzer(executor) { image ->
                                val text = runCatching {
                                    val plane = image.planes[0]
                                    val bytes = ByteArray(plane.buffer.remaining()).also { plane.buffer.get(it) }
                                    val source = PlanarYUVLuminanceSource(bytes, plane.rowStride, image.height, 0, 0, image.width, image.height, false)
                                    reader.decode(BinaryBitmap(HybridBinarizer(source)), mapOf(DecodeHintType.TRY_HARDER to true)).text
                                }.getOrNull()
                                image.close()
                                if (text != null && !done) {
                                    ContextCompat.getMainExecutor(ctx).execute {
                                        if (done) return@execute
                                        val e = onCode(text)
                                        error = e
                                        if (e == null) { done = true; provider.unbindAll() }
                                    }
                                }
                            }
                            provider.unbindAll()
                            provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                        }, ContextCompat.getMainExecutor(ctx))
                        view
                    },
                    onRelease = { runCatching { ProcessCameraProvider.getInstance(it.context).get().unbindAll() } },
                )
            } else if (denied) {
                Text(
                    "Plaintext needs the camera to scan the code. Allow it in Android's settings for Plaintext.",
                    color = Color.White, textAlign = TextAlign.Center, modifier = Modifier.align(Alignment.Center).padding(24.dp),
                )
            }
        }
        ErrorNote(error)
    }
}
