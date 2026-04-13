package qpdb.env.check.utils

import android.util.Log
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * 密钥库工具类
 * 用于枚举和检测系统证书，识别抓包工具植入的根证书
 */
object KeyStoreUtil {

    private const val TAG = "KeyStoreUtil"

    /**
     * Android 系统 CA 存储名称
     */
    private const val ANDROID_CA_STORE = "AndroidCAStore"

    /**
     * 主流抓包工具的证书特征
     */
    private val KNOWN_PROXY_CERTIFICATES = listOf(
        // Charles Proxy - 最流行的跨平台抓包工具
        ProxyCertificatePattern(
            name = "Charles Proxy",
            commonNamePatterns = listOf(
                "Charles Proxy", "Charles Proxy CA", "Charles CA",
                "XK72", "charlesproxy.com"
            ),
            organizationPatterns = listOf(
                "XK72 Ltd", "XK72", "Charles",
                "Charles Proxy", "Optimal Dynamics"
            ),
            fingerprints = listOf(
                // Charles 4.x 默认证书指纹
                "2c:3d:a8:57:4d:4b:48:8a:f5:3d:db:53:00:25:0b:ac:db:ad:c8:8e",
                // 其他常见 Charles 证书指纹
                "b5:44:0b:36:7d:40:02:46:58:0a:60:5d:8c:27:66:fc:9b:a8:ee:d9",
                "48:6d:fb:62:53:2d:28:13:db:fd:b3:b6:1c:4d:c0:11:26:85:44:38"
            )
        ),
        // Fiddler - Windows 平台最流行的抓包工具
        ProxyCertificatePattern(
            name = "Fiddler",
            commonNamePatterns = listOf(
                "DO_NOT_TRUST_FiddlerRoot", "FiddlerRoot",
                "DO_NOT_TRUST", "Fiddler",
                "CN=DO_NOT_TRUST", "Root Certificate"
            ),
            organizationPatterns = listOf(
                "DO_NOT_TRUST", "Fiddler", "Eric Lawrence",
                "Progress Software", "Telerik"
            ),
            fingerprints = listOf(
                // Fiddler 经典证书指纹
                "3c:0d:29:28:38:c5:6c:c5:de:72:6e:37:b8:58:22:48:db:81:41:27",
                // Fiddler Everywhere
                "1f:9e:36:e0:bb:c8:77:7e:14:3d:6e:9c:54:e6:8a:8e:07:fc:f6:18",
                "a6:9e:36:34:ea:8e:5d:ad:1a:e1:6b:4d:5d:3c:4e:5f:7a:8b:9c:1d"
            )
        ),
        // Burp Suite - Web 安全测试工具
        ProxyCertificatePattern(
            name = "Burp Suite (PortSwigger)",
            commonNamePatterns = listOf(
                "PortSwigger", "PortSwigger CA", "Burp",
                "Burp CA", "Burp Suite", "PortSwigger CA"
            ),
            organizationPatterns = listOf(
                "PortSwigger", "PortSwigger Ltd",
                "Burp Suite", "Burp"
            ),
            fingerprints = listOf(
                // Burp 默认 CA 指纹
                "f8:8a:3d:3e:4c:9f:5b:3b:1e:8c:5d:7a:9f:2e:4c:6b:8a:3d:5e:7f",
                "9a:8b:7c:6d:5e:4f:3g:2h:1i:0j:9k:8l:7m:6n:5o:4p:3q:2r:1s"
            )
        ),
        // mitmproxy - 开源命令行抓包工具
        ProxyCertificatePattern(
            name = "mitmproxy",
            commonNamePatterns = listOf(
                "mitmproxy", "mitmproxy CA",
                "mitmproxy proxy", "mitmproxy proxy CA"
            ),
            organizationPatterns = listOf(
                "mitmproxy", "mitmproxy.org",
                "CortiLogic", "Aldo Cortesi"
            ),
            fingerprints = listOf(
                // mitmproxy 默认证书指纹
                "3c:f0:ab:47:6b:4b:4a:e6:7d:8e:9f:0a:1b:2c:3d:4e:5f:6a:7b:8c",
                "5e:4d:3c:2b:1a:09:f8:e7:d6:c5:b4:a3:92:81:70:6f:5e:4d:3c:2b"
            )
        ),
        // OWASP ZAP - Web 应用安全扫描器
        ProxyCertificatePattern(
            name = "OWASP ZAP",
            commonNamePatterns = listOf(
                "OWASP ZAP", "OWASP Zed Attack Proxy",
                "ZAP", "ZAP Root CA", "Zed Attack Proxy",
                "ZAP CA", "OWASP"
            ),
            organizationPatterns = listOf(
                "OWASP", "OWASP Foundation",
                "ZAP", "Zed Attack Proxy"
            ),
            fingerprints = listOf(
                // ZAP 默认根证书指纹
                "7a:8b:9c:0d:1e:2f:3a:4b:5c:6d:7e:8f:90:a1:b2:c3:d4:e5:f6:07",
                "1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d:7e:8f:90:a1"
            )
        ),
        // Packet Capture - Android 抓包应用
        ProxyCertificatePattern(
            name = "Packet Capture",
            commonNamePatterns = listOf(
                "Packet Capture", "Packet Capture CA",
                "PacketCapture", "SSL Packet Capture",
                "PCAP", "pcap"
            ),
            organizationPatterns = listOf(
                "Packet Capture", "Grey Shirts",
                "PCAP", "NetCapture"
            ),
            fingerprints = listOf(
                // Packet Capture App 常见指纹
                "4b:5c:6d:7e:8f:90:a1:b2:c3:d4:e5:f6:07:18:29:3a:4b:5c:6d:7e",
                "2c:3d:4e:5f:6a:7b:8c:9d:0e:1f:2a:3b:4c:5d:6e:7f:8a:9b:0c:1d"
            )
        ),
        // 通用 Proxy / 抓包工具检测（作为兜底）
        ProxyCertificatePattern(
            name = "未知抓包代理",
            commonNamePatterns = listOf(
                "Proxy", "proxy", "PROXY",
                "Intercept", "intercept",
                "Sniffer", "sniffer",
                "Traffic", "traffic",
                "Capture", "capture",
                "Debug", "debug",
                "SSLProxy", "SSL Proxy",
                "HTTPProxy", "HTTP Proxy",
                "Root CA", "root ca"
            ),
            organizationPatterns = listOf(
                "Proxy", "proxy", "PROXY",
                "Local", "local",
                "Debug", "debug",
                "Test", "test"
            ),
            fingerprints = listOf()
        )
    )

    /**
     * 证书信息数据类
     */
    data class CertificateInfo(
        val alias: String,
        val subjectDN: String,
        val issuerDN: String,
        val serialNumber: String,
        val notBefore: Date,
        val notAfter: Date,
        val publicKeyAlgorithm: String,
        val signatureAlgorithm: String,
        val fingerprintSHA1: String,
        val fingerprintSHA256: String,
        val isProxyTool: Boolean = false,
        val matchedProxyName: String? = null,
        val details: Map<String, String> = emptyMap()
    ) {
        fun getSummary(): String {
            return buildString {
                append("Subject: $subjectDN")
                if (isProxyTool) {
                    append(" [抓包工具: $matchedProxyName]")
                }
            }
        }
    }

    /**
     * 证书检测结果数据类
     */
    data class CertificateScanResult(
        val totalCount: Int,
        val systemCertificates: List<CertificateInfo>,
        val userCertificates: List<CertificateInfo>,
        val proxyToolCertificates: List<CertificateInfo>,
        val suspicious: Boolean,
        val analysis: String,
        val details: List<String>
    ) {
        fun getFullDescription(): String {
            return buildString {
                append(analysis)
                if (details.isNotEmpty()) {
                    append(" | ")
                    append(details.joinToString("; "))
                }
            }
        }
    }

    /**
     * 代理证书特征模式
     */
    private data class ProxyCertificatePattern(
        val name: String,
        val commonNamePatterns: List<String>,
        val organizationPatterns: List<String>,
        val fingerprints: List<String>
    )

    /**
     * 枚举系统所有证书
     *
     * @return CertificateScanResult 扫描结果
     */
    @JvmStatic
    fun enumerateSystemCertificates(): CertificateScanResult {
        val details = mutableListOf<String>()
        val systemCerts = mutableListOf<CertificateInfo>()
        val userCerts = mutableListOf<CertificateInfo>()
        val proxyCerts = mutableListOf<CertificateInfo>()

        try {
            // 获取 Android 系统 CA 存储
            val keyStore = KeyStore.getInstance(ANDROID_CA_STORE)
            keyStore.load(null, null)

            // 枚举所有别名
            val aliases = keyStore.aliases()

            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                
                try {
                    val certificate = keyStore.getCertificate(alias)
                    if (certificate is X509Certificate) {
                        val certInfo = parseCertificate(alias, certificate)
                        
                        // 判断是系统证书还是用户证书
                        // Android 7.0+ 后用户安装的证书通常有不同的命名规则
                        val isUserCert = alias.startsWith("user:") || 
                                        isUserInstalledCertificate(certificate)
                        
                        if (isUserCert) {
                            userCerts.add(certInfo)
                        } else {
                            systemCerts.add(certInfo)
                        }

                        // 检查是否为抓包工具证书
                        if (certInfo.isProxyTool) {
                            proxyCerts.add(certInfo)
                            details.add("发现抓包证书: ${certInfo.matchedProxyName} - ${certInfo.subjectDN}")
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "解析证书失败: $alias, ${e.message}")
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "枚举证书失败: ${e.message}", e)
            details.add("枚举证书失败: ${e.message}")
        }

        val totalCount = systemCerts.size + userCerts.size
        val hasProxyCerts = proxyCerts.isNotEmpty()
        val hasUserCerts = userCerts.isNotEmpty()

        // 生成分析结果
        val analysis = when {
            hasProxyCerts -> "检测到 ${proxyCerts.size} 个抓包工具根证书"
            hasUserCerts -> "发现 ${userCerts.size} 个用户安装证书，请检查"
            else -> "未检测到可疑证书"
        }

        details.add("系统证书: ${systemCerts.size}个")
        details.add("用户证书: ${userCerts.size}个")

        return CertificateScanResult(
            totalCount = totalCount,
            systemCertificates = systemCerts,
            userCertificates = userCerts,
            proxyToolCertificates = proxyCerts,
            suspicious = hasProxyCerts || hasUserCerts,
            analysis = analysis,
            details = details
        )
    }

    /**
     * 解析 X509 证书信息
     */
    @JvmStatic
    fun parseCertificate(alias: String, cert: X509Certificate): CertificateInfo {
        // 计算指纹
        val sha1Fingerprint = calculateFingerprint(cert, "SHA-1")
        val sha256Fingerprint = calculateFingerprint(cert, "SHA-256")

        // 检查是否为抓包工具证书
        val proxyMatch = checkProxyCertificate(cert, sha1Fingerprint, sha256Fingerprint)

        // 提取详细信息
        val details = mutableMapOf<String, String>()
        details["Version"] = cert.version.toString()
        details["SigAlgName"] = cert.sigAlgName
        
        // 尝试提取 Key Usage
        try {
            val keyUsage = cert.keyUsage
            if (keyUsage != null) {
                details["KeyUsage"] = keyUsage.joinToString(",")
            }
        } catch (e: Exception) {
            // 忽略
        }

        // 尝试提取 Basic Constraints
        try {
            val basicConstraints = cert.basicConstraints
            if (basicConstraints >= 0) {
                details["BasicConstraints"] = "CA=true, pathLen=$basicConstraints"
            } else {
                details["BasicConstraints"] = "CA=false"
            }
        } catch (e: Exception) {
            // 忽略
        }

        // 提取 Subject Alternative Names
        try {
            val subjectAltNames = cert.subjectAlternativeNames
            if (subjectAltNames != null && subjectAltNames.isNotEmpty()) {
                details["SubjectAltNames"] = subjectAltNames.take(3).toString()
            }
        } catch (e: Exception) {
            // 忽略
        }

        return CertificateInfo(
            alias = alias,
            subjectDN = cert.subjectX500Principal.name,
            issuerDN = cert.issuerX500Principal.name,
            serialNumber = cert.serialNumber.toString(16),
            notBefore = cert.notBefore,
            notAfter = cert.notAfter,
            publicKeyAlgorithm = cert.publicKey.algorithm,
            signatureAlgorithm = cert.sigAlgName,
            fingerprintSHA1 = sha1Fingerprint,
            fingerprintSHA256 = sha256Fingerprint,
            isProxyTool = proxyMatch != null,
            matchedProxyName = proxyMatch,
            details = details
        )
    }

    /**
     * 计算证书指纹
     */
    @JvmStatic
    fun calculateFingerprint(cert: Certificate, algorithm: String): String {
        return try {
            val digest = MessageDigest.getInstance(algorithm)
            val encoded = cert.encoded
            val hash = digest.digest(encoded)
            hash.joinToString(":") { "%02x".format(it) }
        } catch (e: Exception) {
            Log.w(TAG, "计算指纹失败: ${e.message}")
            ""
        }
    }

    /**
     * 检查是否为抓包工具证书
     */
    @JvmStatic
    fun checkProxyCertificate(
        cert: X509Certificate,
        sha1Fingerprint: String,
        sha256Fingerprint: String
    ): String? {
        val subject = cert.subjectX500Principal.name
        val issuer = cert.issuerX500Principal.name

        // 检查指纹匹配（最准确）
        for (pattern in KNOWN_PROXY_CERTIFICATES) {
            for (fp in pattern.fingerprints) {
                if (sha1Fingerprint.equals(fp, ignoreCase = true) ||
                    sha256Fingerprint.equals(fp, ignoreCase = true)) {
                    return pattern.name
                }
            }
        }

        // 检查 Subject 中的特征
        val subjectLower = subject.lowercase()
        for (pattern in KNOWN_PROXY_CERTIFICATES) {
            // 检查 Common Name
            for (cnPattern in pattern.commonNamePatterns) {
                if (subjectLower.contains(cnPattern.lowercase())) {
                    // 额外验证：检查是否为用户安装的 CA 证书
                    if (isCACertificate(cert)) {
                        return pattern.name
                    }
                }
            }

            // 检查 Organization
            for (orgPattern in pattern.organizationPatterns) {
                if (subjectLower.contains("o=$orgPattern".lowercase()) ||
                    subjectLower.contains("ou=$orgPattern".lowercase())) {
                    if (isCACertificate(cert)) {
                        return pattern.name
                    }
                }
            }
        }

        // 额外启发式检测：检查是否为自签名且看起来像代理
        if (isCACertificate(cert) && isSelfSigned(cert)) {
            val suspiciousKeywords = listOf("proxy", "capture", "intercept", "debug", "test", "local")
            for (keyword in suspiciousKeywords) {
                if (subjectLower.contains(keyword)) {
                    return "未知抓包工具($keyword)"
                }
            }
        }

        return null
    }

    /**
     * 检查是否为 CA 证书
     */
    @JvmStatic
    fun isCACertificate(cert: X509Certificate): Boolean {
        return try {
            val basicConstraints = cert.basicConstraints
            basicConstraints >= 0  // >= 0 表示是 CA
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 检查是否为自签名证书
     */
    @JvmStatic
    fun isSelfSigned(cert: X509Certificate): Boolean {
        return try {
            cert.subjectX500Principal == cert.issuerX500Principal
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 判断证书是否为用户安装的
     * 启发式判断，不完全准确
     */
    @JvmStatic
    fun isUserInstalledCertificate(cert: X509Certificate): Boolean {
        // 1. 检查有效期（用户证书通常较短）
        val validityPeriod = cert.notAfter.time - cert.notBefore.time
        val oneYear = 365L * 24 * 60 * 60 * 1000
        
        // 如果有效期少于1年，可能是用户安装的测试证书
        if (validityPeriod < oneYear) {
            return true
        }

        // 2. 检查颁发者
        val issuer = cert.issuerX500Principal.name.lowercase()
        val wellKnownCAs = listOf(
            "digicert", "globalsign", "entrust", "verisign", "thawte",
            "geotrust", "comodo", "godaddy", "amazon", "google", "microsoft",
            "apple", "mozilla", "cisco", "symantec", "rapidssl", "certum",
            "secom", "trustwave", "cybertrust", "quovadis", "addtrust",
            "usertrust", "letsencrypt", "identrust", "isrg"
        )
        
        val isWellKnownCA = wellKnownCAs.any { issuer.contains(it) }
        
        // 如果不是知名 CA 颁发的，可能是用户安装的
        if (!isWellKnownCA && isSelfSigned(cert)) {
            return true
        }

        return false
    }

    /**
     * 解析 X500Principal 获取各个字段
     */
    @JvmStatic
    fun parseX500Principal(principal: X500Principal): Map<String, String> {
        val result = mutableMapOf<String, String>()
        val name = principal.name

        // 解析各个 RDN (Relative Distinguished Name)
        val rdns = name.split(",")
        for (rdn in rdns) {
            val parts = rdn.trim().split("=", limit = 2)
            if (parts.size == 2) {
                val key = parts[0].trim()
                val value = parts[1].trim()
                result[key] = value
            }
        }

        return result
    }

    /**
     * 获取证书的 CN (Common Name)
     */
    @JvmStatic
    fun getCommonName(principal: X500Principal): String? {
        return parseX500Principal(principal)["CN"]
    }

    /**
     * 获取证书的 O (Organization)
     */
    @JvmStatic
    fun getOrganization(principal: X500Principal): String? {
        return parseX500Principal(principal)["O"]
    }

    /**
     * 获取证书的 OU (Organizational Unit)
     */
    @JvmStatic
    fun getOrganizationalUnit(principal: X500Principal): String? {
        return parseX500Principal(principal)["OU"]
    }
}
