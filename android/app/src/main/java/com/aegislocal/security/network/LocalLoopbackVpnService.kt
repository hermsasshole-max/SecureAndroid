package com.aegislocal.security.network

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Local on-device loopback VpnService (tun0 10.215.173.1/30).
 * Inspects outbound DNS QNAMEs locally in memory and forwards clean queries
 * directly via protected physical sockets without external VPN server routing.
 */
class LocalLoopbackVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunInterface: ParcelFileDescriptor? = null

    companion object {
        const val ACTION_START = "com.aegislocal.security.START_LOCAL_VPN"
        const val ACTION_STOP = "com.aegislocal.security.STOP_LOCAL_VPN"
        private const val CHANNEL_ID = "aegis_local_vpn_channel"
        private const val NOTIFICATION_ID = 4101
        private const val UPSTREAM_DNS = "1.1.1.1"
        private const val VIRTUAL_DNS_INTERCEPT = "10.215.173.2"

        @Volatile
        var isTunnelRunning: Boolean = false
            private set
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopLocalTunnel()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        promoteToForeground()
        startLocalDnsLoopbackTunnel()
        return START_STICKY
    }

    private fun promoteToForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            "AegisLocal Loopback DNS Guard",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "On-device DNS & rogue Wi-Fi MITM guard (no external server routing)"
        }
        manager.createNotificationChannel(channel)

        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AegisLocal Loopback Guard Active")
            .setContentText("Inspecting DNS locally on tun0 · Zero external traffic routing")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun startLocalDnsLoopbackTunnel() {
        if (tunInterface != null) {
            isTunnelRunning = true
            return
        }

        val builder = Builder()
            .setSession("AegisLocal On-Device DNS Guard")
            .setMtu(1500)
            .addAddress("10.215.173.1", 30)
            .addDnsServer(VIRTUAL_DNS_INTERCEPT)
            .addRoute(VIRTUAL_DNS_INTERCEPT, 32)
            .setBlocking(true)

        runCatching { builder.addDisallowedApplication(packageName) }

        val established = builder.establish() ?: return
        tunInterface = established
        isTunnelRunning = true
        val descriptor = established.fileDescriptor

        serviceScope.launch {
            try {
                FileInputStream(descriptor).use { input ->
                    FileOutputStream(descriptor).use { output ->
                        val packetBuffer = ByteBuffer.allocate(32767)
                        while (isActive && tunInterface != null) {
                            val length = input.read(packetBuffer.array())
                            if (length > 0) {
                                packetBuffer.limit(length)
                                runCatching { handleIpv4UdpDnsFrame(packetBuffer, output) }
                                packetBuffer.clear()
                            }
                        }
                    }
                }
            } catch (_: Exception) {
                isTunnelRunning = false
            }
        }
    }

    private fun handleIpv4UdpDnsFrame(packet: ByteBuffer, tunOutput: FileOutputStream) {
        val versionAndIhl = packet.get(0).toInt() and 0xFF
        if ((versionAndIhl ushr 4) != 4) return
        val ipHeaderLen = (versionAndIhl and 0x0F) * 4
        val protocol = packet.get(9).toInt() and 0xFF
        if (protocol != 17 || packet.limit() < ipHeaderLen + 8) return

        val dnsPayloadOffset = ipHeaderLen + 8
        val dnsPayloadLen = packet.limit() - dnsPayloadOffset
        if (dnsPayloadLen <= 12) return

        val dnsBytes = ByteArray(dnsPayloadLen)
        packet.position(dnsPayloadOffset)
        packet.get(dnsBytes)

        val queriedDomain = parseDnsQName(dnsBytes)
        if (queriedDomain != null && isLocallyBlockedPhishingDomain(queriedDomain)) {
            val nxResponse = synthesizeDnsNxDomainFrame(packet, ipHeaderLen, dnsBytes)
            tunOutput.write(nxResponse)
            return
        }

        DatagramSocket().use { upstreamSocket ->
            if (!protect(upstreamSocket)) return
            upstreamSocket.soTimeout = 2500
            val outReq = DatagramPacket(
                dnsBytes,
                dnsBytes.size,
                InetAddress.getByName(UPSTREAM_DNS),
                53
            )
            upstreamSocket.send(outReq)

            val respBuf = ByteArray(1500)
            val inResp = DatagramPacket(respBuf, respBuf.size)
            upstreamSocket.receive(inResp)

            val wrappedIpUdp = buildIpv4UdpReply(packet, ipHeaderLen, respBuf, inResp.length)
            tunOutput.write(wrappedIpUdp)
        }
    }

    private fun parseDnsQName(dnsPayload: ByteArray): String? {
        val labels = mutableListOf<String>()
        var idx = 12
        while (idx < dnsPayload.size) {
            val len = dnsPayload[idx].toInt() and 0xFF
            if (len == 0) break
            if (idx + 1 + len > dnsPayload.size) return null
            labels += String(dnsPayload, idx + 1, len, Charsets.UTF_8)
            idx += 1 + len
        }
        return labels.joinToString(".").lowercase().takeIf { it.isNotEmpty() }
    }

    private fun isLocallyBlockedPhishingDomain(domain: String): Boolean {
        return domain.startsWith("xn--") && (domain.contains("pypal") || domain.contains("gogle"))
    }

    private fun synthesizeDnsNxDomainFrame(
        reqPacket: ByteBuffer,
        ipHeaderLen: Int,
        dnsReq: ByteArray
    ): ByteArray {
        val dnsReply = dnsReq.copyOf()
        dnsReply[2] = 0x81.toByte()
        dnsReply[3] = 0x83.toByte()
        return buildIpv4UdpReply(reqPacket, ipHeaderLen, dnsReply, dnsReply.size)
    }

    private fun buildIpv4UdpReply(
        req: ByteBuffer,
        ipHeaderLen: Int,
        udpPayload: ByteArray,
        payloadLen: Int
    ): ByteArray {
        val totalLen = ipHeaderLen + 8 + payloadLen
        val out = ByteBuffer.allocate(totalLen)
        val header = ByteArray(ipHeaderLen)
        req.position(0)
        req.get(header)

        for (i in 0..3) {
            val tmp = header[12 + i]
            header[12 + i] = header[16 + i]
            header[16 + i] = tmp
        }
        header[2] = ((totalLen ushr 8) and 0xFF).toByte()
        header[3] = (totalLen and 0xFF).toByte()
        header[10] = 0
        header[11] = 0
        val csum = computeIpv4Checksum(header)
        header[10] = ((csum ushr 8) and 0xFF).toByte()
        header[11] = (csum and 0xFF).toByte()
        out.put(header)

        val clientPort = req.getShort(ipHeaderLen)
        val serverPort = req.getShort(ipHeaderLen + 2)
        out.putShort(serverPort)
        out.putShort(clientPort)
        out.putShort((8 + payloadLen).toShort())
        out.putShort(0)
        out.put(udpPayload, 0, payloadLen)
        return out.array()
    }

    private fun computeIpv4Checksum(header: ByteArray): Int {
        var sum = 0
        var i = 0
        while (i < header.size) {
            val word = ((header[i].toInt() and 0xFF) shl 8) or (header[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    override fun onRevoke() {
        stopLocalTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopLocalTunnel()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun stopLocalTunnel() {
        isTunnelRunning = false
        runCatching { tunInterface?.close() }
        tunInterface = null
    }
}
