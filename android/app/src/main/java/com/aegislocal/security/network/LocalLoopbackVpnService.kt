package com.aegislocal.security.network

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineExceptionHandler
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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.log2

/**
 * Local on-device loopback VpnService (tun0 10.215.173.1/30).
 * Acts as a zero-server DNS Threat Sinkhole: blocks Punycode homographs, RAT Dynamic DNS C2s,
 * high-entropy DGA / DNS-tunneling queries, and user-blocked domains with NXDOMAIN locally,
 * while forwarding clean queries to Malware-Blocking resolvers (1.1.1.2 / 9.9.9.9).
 */
class LocalLoopbackVpnService : VpnService() {

    private val vpnErrorHandler = CoroutineExceptionHandler { _, throwable ->
        Log.e("LocalLoopbackVpn", "Caught tunnel coroutine error", throwable)
    }
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + vpnErrorHandler)
    private var tunInterface: ParcelFileDescriptor? = null

    companion object {
        const val ACTION_START = "com.aegislocal.security.START_LOCAL_VPN"
        const val ACTION_STOP = "com.aegislocal.security.STOP_LOCAL_VPN"
        private const val CHANNEL_ID = "aegis_local_vpn_channel"
        private const val NOTIFICATION_ID = 4101
        private const val PRIMARY_MALWARE_DNS = "1.1.1.2"
        private const val FALLBACK_MALWARE_DNS = "9.9.9.9"
        private const val VIRTUAL_DNS_INTERCEPT = "10.215.173.2"

        private val DYNAMIC_DNS_C2_SUFFIXES = listOf(
            "duckdns.org",
            "ddns.net",
            "no-ip.org",
            "no-ip.biz",
            "hopto.org",
            "zapto.org",
            "sytes.net",
            "myftp.biz",
            "myftp.org",
            "servehttp.com",
            "onion.ws",
            "tor2web.org"
        )

        private val customBlockedDomains: MutableSet<String> = ConcurrentHashMap.newKeySet()

        @Volatile
        var dgaEntropyGuardEnabled: Boolean = true

        @Volatile
        var punycodeHomographBlockEnabled: Boolean = true

        @Volatile
        var dynamicDnsC2BlockEnabled: Boolean = true

        @Volatile
        var isTunnelRunning: Boolean = false
            private set

        val inspectedDnsCount = AtomicLong(0L)
        val blockedDnsCount = AtomicLong(0L)

        @Volatile
        var onThreatSinkholed: ((domain: String, reason: String) -> Unit)? = null

        fun updateSinkholePolicy(
            dgaGuard: Boolean,
            punycodeBlock: Boolean,
            ddnsBlock: Boolean,
            blockedDomains: Collection<String>
        ) {
            dgaEntropyGuardEnabled = dgaGuard
            punycodeHomographBlockEnabled = punycodeBlock
            dynamicDnsC2BlockEnabled = ddnsBlock
            customBlockedDomains.clear()
            blockedDomains.map { it.trim().lowercase() }
                .filter { it.isNotEmpty() }
                .forEach { customBlockedDomains.add(it) }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopLocalTunnel()
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
            stopSelf()
            return START_NOT_STICKY
        }

        runCatching {
            promoteToForeground()
            startLocalDnsLoopbackTunnel()
        }.onFailure { err ->
            Log.e("LocalLoopbackVpn", "Failed to start local tunnel", err)
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    private fun promoteToForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            "AegisLocal Live Shield DNS Sinkhole",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "On-device anti-intrusion DNS sinkhole & malware guard (zero external routing)"
        }
        manager.createNotificationChannel(channel)

        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AegisLocal Live Shield Active")
            .setContentText("Sinkholing C2, DGA & phishing DNS on tun0 · Resolver 1.1.1.2")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            try {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } catch (_: Throwable) {
                startForeground(NOTIFICATION_ID, notification)
            }
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
            .setSession("AegisLocal Live Shield")
            .setMtu(1500)
            .addAddress("10.215.173.1", 30)
            .addDnsServer(VIRTUAL_DNS_INTERCEPT)
            .addRoute(VIRTUAL_DNS_INTERCEPT, 32)
            .setBlocking(true)

        runCatching { builder.addDisallowedApplication(packageName) }

        val established = runCatching { builder.establish() }.getOrNull() ?: return
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
        if (queriedDomain != null) {
            inspectedDnsCount.incrementAndGet()
            val blockReason = evaluateDomainSinkholeReason(queriedDomain)
            if (blockReason != null) {
                blockedDnsCount.incrementAndGet()
                runCatching { onThreatSinkholed?.invoke(queriedDomain, blockReason) }
                val nxResponse = synthesizeDnsNxDomainFrame(packet, ipHeaderLen, dnsBytes)
                tunOutput.write(nxResponse)
                return
            }
        }

        val replyPayload = forwardToMalwareBlockingDns(dnsBytes, PRIMARY_MALWARE_DNS)
            ?: forwardToMalwareBlockingDns(dnsBytes, FALLBACK_MALWARE_DNS)
            ?: return

        val wrappedIpUdp = buildIpv4UdpReply(packet, ipHeaderLen, replyPayload.first, replyPayload.second)
        tunOutput.write(wrappedIpUdp)
    }

    private fun forwardToMalwareBlockingDns(
        dnsBytes: ByteArray,
        upstreamIp: String
    ): Pair<ByteArray, Int>? {
        return runCatching {
            DatagramSocket().use { upstreamSocket ->
                if (!protect(upstreamSocket)) return null
                upstreamSocket.soTimeout = 2200
                val outReq = DatagramPacket(
                    dnsBytes,
                    dnsBytes.size,
                    InetAddress.getByName(upstreamIp),
                    53
                )
                upstreamSocket.send(outReq)

                val respBuf = ByteArray(1500)
                val inResp = DatagramPacket(respBuf, respBuf.size)
                upstreamSocket.receive(inResp)
                Pair(respBuf, inResp.length)
            }
        }.getOrNull()
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

    private fun evaluateDomainSinkholeReason(domain: String): String? {
        for (blocked in customBlockedDomains) {
            if (domain == blocked || domain.endsWith(".$blocked")) {
                return "Sinkholed by custom encrypted blocklist rule ($blocked)"
            }
        }

        val labels = domain.split('.')
        if (punycodeHomographBlockEnabled && labels.any { it.startsWith("xn--") }) {
            return "Blocked Punycode IDN homograph DNS query ($domain)"
        }

        if (dynamicDnsC2BlockEnabled) {
            val matchedDdns = DYNAMIC_DNS_C2_SUFFIXES.firstOrNull { suffix ->
                domain == suffix || domain.endsWith(".$suffix")
            }
            if (matchedDdns != null) {
                return "Blocked Dynamic DNS RAT/stalkerware C2 endpoint ($matchedDdns)"
            }
        }

        if (dgaEntropyGuardEnabled && labels.size >= 2) {
            val sub = labels.first()
            val hasMix = sub.any { it.isDigit() } && sub.any { it.isLetter() }
            if (sub.length >= 16) {
                val entropy = calculateShannonEntropy(sub)
                if ((entropy >= 3.85 && hasMix) || (sub.length >= 24 && entropy >= 3.95)) {
                    return "Blocked high-entropy DGA / DNS tunneling beacon (${"%.2f".format(entropy)} bits/char)"
                }
            }
        }

        return null
    }

    private fun calculateShannonEntropy(label: String): Double {
        if (label.isEmpty()) return 0.0
        val counts = HashMap<Char, Int>()
        for (c in label) {
            counts[c] = (counts[c] ?: 0) + 1
        }
        val len = label.length.toDouble()
        var entropy = 0.0
        for (count in counts.values) {
            val p = count / len
            entropy -= p * log2(p)
        }
        return entropy
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
