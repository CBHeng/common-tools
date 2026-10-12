package io.github.cboheng.commontools.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES/GCM/NoPadding 認證加密，外加「時效性」包裝。
 *
 * <h2>為什麼用 GCM</h2>
 * GCM 是 AEAD（Authenticated Encryption with Associated Data）模式：一次同時提供
 * 機密性與完整性。密文被改動一個 bit，{@code doFinal} 就會拋出
 * {@code AEADBadTagException}，不會回傳可疑的明文。相對地 CBC 只加密不認證，
 * 必須自己外掛 HMAC，順序弄錯就會踩到 padding oracle 這類經典漏洞。
 *
 * <h2>Token 格式</h2>
 * <pre>
 *   Base64URL( VERSION(1) | IV(12) | CIPHERTEXT(n) | TAG(16) )
 * </pre>
 * 其中 {@code CIPHERTEXT | TAG} 是 JCE 的 {@code doFinal} 直接吐出的結果
 * （Java 的 GCM 實作會把 tag 接在密文尾端）。
 * <p>注意 {@code kid} 刻意<b>不在</b> token 裡，詳見 {@link KeyRef}。
 *
 * <h2>金鑰識別碼 kid</h2>
 * 每次加解密都需要一個 {@link KeyRef}，也就是「金鑰 + 它的 kid」。
 * kid 會被餵進 GCM 的 AAD，所以它不加密、但納入認證範圍。帶來兩個效果：
 * <ul>
 *   <li><b>金鑰身分被綁進密文</b>——拿對的金鑰配錯的 kid，一樣解不開。</li>
 *   <li><b>改 kid 等於全面撤銷</b>——不換金鑰、只改 kid，所有已發出的 token 立刻失效。</li>
 * </ul>
 *
 * <h2>時效性放在哪：密文內</h2>
 * {@code expired} 與 {@code subject} 一起被加密，<b>不是</b>放在明文 header。
 * 代價是必須先完成解密才知道 token 早就過期；換來的是旁觀者連「這張票何時到期」
 * 都看不到。若你的場景需要「不解密就先擋掉過期請求」（省 CPU、抗大量過期 token
 * 灌入），做法是把時戳改放 AAD——Fernet 的 timestamp 就是明文且納入 HMAC、
 * Branca 更是直接把 timestamp 當 AAD header。這是一個明確的取捨，不是對錯。
 *
 * <h2>誰負責判斷過期：應用層</h2>
 * 本類別只負責「安全地把 {@code expired} 帶進密文、再帶出來」，<b>不會自動檢查過期</b>。
 * 判斷的時機、時鐘來源、是否容許時鐘偏移，都是應用層的決定。
 * 取得 {@link Payload} 之後請自行呼叫 {@link Payload#requireNotExpired(Instant)}
 * 或 {@link Payload#isExpired(Instant)}。
 * <p>這樣切分的代價很明確：呼叫端漏掉檢查時，時效性會<b>完全失效且毫無徵兆</b>。
 * 所以典型用法請把兩步串成一行，讓「少做了檢查」在 code review 時看得出來：
 * <pre>{@code
 * Payload payload = AesGcmHelper.decryptPayload(token, key)
 *         .requireNotExpired(Instant.now());
 * }</pre>
 *
 * <h2>執行緒安全</h2>
 * 全部 static method 皆可並行呼叫。{@link Cipher} 本身<b>不是</b> thread-safe，
 * 所以這裡每次加解密都 {@code getInstance} 新建一個，絕不共用 static 實例——
 * 共用 Cipher 是多執行緒下最常見的加密災難。{@link SecureRandom} 是
 * thread-safe，因此可以安全地共用一份。
 *
 * <h2>最重要的一條規則：IV 絕不重複</h2>
 * 同一把 key 配同一個 IV 加密兩次，GCM 的安全性會直接崩潰（可還原明文差值、
 * 甚至偽造 tag）。本類別每次加密都用 {@link SecureRandom} 產生全新的 12-byte IV，
 * 呼叫端無法也不需要自己指定 IV。
 * 依 NIST SP 800-38D §8.3，在隨機 IV 的作法下，同一把 key 的加密次數應限制在
 * 2^32 次以內，以把 nonce 碰撞機率壓在 2^-32 以下。真的會逼近這個量級時，
 * 要做的是輪替金鑰，而不是加大 IV。
 *
 * <h2>敏感 bytes 用完即清零</h2>
 * 金鑰與明文的暫存 {@code byte[]}，在 {@code finally} 裡以 {@code Arrays.fill(…, 0)} 覆寫。
 * <ul>
 *   <li><b>防的是殘留，不是洩漏。</b>這些陣列在 method 結束後本來就會被 GC 回收；
 *       問題在於回收時機不確定，回收前內容仍完整留在 heap 上，可能出現在 heap dump、
 *       crash dump 或記憶體分析工具裡。主動覆寫把這段時間縮到最短。</li>
 *   <li><b>清掉的都是副本。</b>{@code SecretKeySpec} 建構時會複製傳入的陣列，
 *       {@code getEncoded()} 每次呼叫都回傳新陣列，{@code new String(bytes, …)} 也會複製內容
 *       ——所以清零不影響金鑰或結果本身。</li>
 *   <li><b>放在 {@code finally}。</b>驗證失敗、拋例外的路徑一樣會清。</li>
 *   <li><b>盡力而為，不是保證。</b>{@code String} 是 immutable、無法清零（例如傳入的 Base64
 *       金鑰字串）；{@code SecretKeySpec} 內部的那份金鑰會跟著 {@link KeyRef} 存活；
 *       GC 搬移物件時舊位置也可能殘留內容。這是縱深防禦，降低暴露時間而非消除。</li>
 * </ul>
 */
public final class AesGcmHelper {

    /** AES-GCM 不需要 padding：GCM 是 counter 模式，明文長度不必對齊 block。 */
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";

    /** 金鑰長度固定為 AES-256，單一規格，沒有可選的強度。 */
    private static final int KEY_BITS = 256;
    private static final int KEY_BYTES = KEY_BITS / 8;

    /** 96-bit IV。NIST SP 800-38D 建議值，也是唯一不需額外做 GHASH 衍生的長度。 */
    private static final int IV_LENGTH = 12;

    /** 128-bit 認證標籤，GCM 規格允許的最長、也是唯一該用在通用場景的長度。 */
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;

    /** Token 格式版號。日後若改格式，舊 token 能被明確辨識而非默默解錯。 */
    private static final byte VERSION = 0x01;

    /** payload 內 {@code expired} 欄位固定佔 8 bytes（long, big-endian）。 */
    private static final int EXPIRED_FIELD_LENGTH = Long.BYTES;

    /** Token 的最小合法長度：version + IV + tag，對應明文為空的情形。 */
    private static final int MIN_TOKEN_BYTES = 1 + IV_LENGTH + TAG_LENGTH_BYTES;

    /** thread-safe，可共用。 */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** 用 URL-safe 字元表且不帶 padding，token 可直接放進 URL、header、cookie。 */
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private AesGcmHelper() {
        throw new AssertionError("工具類別，不該被實例化");
    }

    // ------------------------------------------------------------------
    // Payload：帶時效性的資料載體
    // ------------------------------------------------------------------

    /**
     * 要被加密的內容：一個主體識別 {@code subject} 與一個絕對到期時間 {@code expired}。
     *
     * <p>{@code expired} 一律被截斷到<b>毫秒</b>。原因是 token 內只存
     * {@code epochMilli}（8 bytes），若不在建構時就截斷，
     * {@code new Payload(s, t)} 與解密後拿回的 Payload 會因為奈秒被丟掉而不相等，
     * 那是個很難查的 bug。在型別邊界就把它消滅掉。
     *
     * @param subject 主體識別，例如 userId、訂單號、session id。不可為 null，可為空字串。
     * @param expired 絕對到期時間（含奈秒會被截到毫秒）。不可為 null。
     */
    public record Payload(String subject, Instant expired) {

        public Payload {
            Objects.requireNonNull(subject, "subject 不可為 null");
            Objects.requireNonNull(expired, "expired 不可為 null");

            expired = expired.truncatedTo(ChronoUnit.MILLIS);
            try {
                // 提早失敗：序列化時才 overflow 會變成難解釋的 ArithmeticException。
                expired.toEpochMilli();
            } catch (ArithmeticException e) {
                throw new IllegalArgumentException(
                        "expired 超出可表示範圍（必須能表示為 epoch milli）: " + expired, e);
            }
        }

        /**
         * 以「現在 + ttl」產生到期時間，對應「發一張只有效 N 分鐘的票」這種最常見用法。
         *
         * @param ttl 有效期長度，必須為正。
         */
        public static Payload validFor(String subject, Duration ttl) {
            Objects.requireNonNull(ttl, "ttl 不可為 null");
            if (ttl.isNegative() || ttl.isZero()) {
                throw new IllegalArgumentException("ttl 必須為正數，收到: " + ttl);
            }
            return new Payload(subject, Instant.now().plus(ttl));
        }

        /**
         * 判斷是否已過期。採 {@code now >= expired} 即算過期，
         * 到期的那一瞬間不給寬限。
         */
        public boolean isExpired(Instant now) {
            Objects.requireNonNull(now, "now 不可為 null");
            return !now.isBefore(expired);
        }

        /**
         * 已過期就拋 {@link TokenExpiredException}，否則原封不動回傳自己，方便串接。
         *
         * <p>刻意要求傳入 {@code now}，而不是在裡面呼叫 {@code Instant.now()}：
         * 時鐘一旦寫死在內部，測試就無法凍結時間，應用層也無從容許分散式環境的
         * 時鐘偏移。多打一個參數，換到的是可測試性與可控性。
         *
         * @return 未過期的自己，可直接接續使用
         * @throws TokenExpiredException 已過期
         */
        public Payload requireNotExpired(Instant now) {
            if (isExpired(now)) {
                throw new TokenExpiredException(expired);
            }
            return this;
        }

        /** 刻意覆寫：避免 record 預設的 toString 把 subject 內容寫進 log。 */
        @Override
        public String toString() {
            return "Payload[subject=<已隱藏, " + subject.length() + " chars>, expired=" + expired + "]";
        }
    }

    // ------------------------------------------------------------------
    // KeyRef：金鑰 + 金鑰識別碼
    // ------------------------------------------------------------------

    /**
     * 一把 AES 金鑰，以及它的識別碼 {@code kid}（key id）。
     *
     * <p>建構時驗證金鑰：演算法為 AES、長度為 256 bits，不符即拋
     * {@link IllegalArgumentException}。因此金鑰設定錯誤會在建立 {@code KeyRef} 的當下浮現，
     * 與加解密時的 {@link TokenInvalidException}（token 格式錯或被篡改）明確區分。
     *
     * @param key AES-256 金鑰；必須可匯出（{@code getEncoded()} 不為 null），否則無法驗證長度
     * @param kid 金鑰識別碼，不可為空。可以是版本號（{@code "v3"}）、日期（{@code "2026-10"}）
     *            或 UUID；只要加解密兩端一致即可。
     */
    public record KeyRef(SecretKey key, String kid) {

        /** 防手滑用的上限，不是技術限制。AAD 本身可任意長，但 kid 本來就該是短字串。 */
        private static final int MAX_KID_BYTES = 256;

        public KeyRef {
            Objects.requireNonNull(key, "key 不可為 null");
            Objects.requireNonNull(kid, "kid 不可為 null");
            requireAes256(key);
            if (kid.isEmpty()) {
                // 空 kid 會讓 AAD 退化成只剩版號，與「沒有 kid 概念」的格式撞在一起。
                throw new IllegalArgumentException("kid 不可為空字串");
            }
            int kidBytes = kid.getBytes(StandardCharsets.UTF_8).length;
            if (kidBytes > MAX_KID_BYTES) {
                throw new IllegalArgumentException(
                        "kid 過長：" + kidBytes + " bytes，上限 " + MAX_KID_BYTES
                                + "（kid 應該是短識別碼，不是用來夾帶資料的欄位）");
            }
        }

        /**
         * 從金鑰的 raw bytes 與 kid 建立，例如 KMS 回傳的 data key。
         *
         * <p>{@code raw} 會被複製一份保存，不會被修改；用完後是否清零由呼叫端決定。
         */
        public static KeyRef of(byte[] raw, String kid) {
            Objects.requireNonNull(raw, "raw 不可為 null");
            return new KeyRef(new SecretKeySpec(raw, KEY_ALGORITHM), kid);
        }

        /**
         * 從 Base64 金鑰字串與 kid 建立，同時接受標準與 URL-safe 字元表。
         *
         * <p>金鑰與 kid 從哪裡來（環境變數、KMS、設定檔）是應用層的事，本工具不介入；
         * 這個方法只負責把「讀出來的 Base64 字串」轉成可用的 {@code KeyRef}。
         */
        public static KeyRef ofBase64(String base64Key, String kid) {
            Objects.requireNonNull(base64Key, "base64Key 不可為 null");
            byte[] raw;
            try {
                // URL decoder 不吃 '+' '/'，所以先轉換，讓兩種字元表都能進來。
                raw = DECODER.decode(base64Key.replace('+', '-').replace('/', '_').replace("=", ""));
            } catch (IllegalArgumentException e) {
                throw new CryptoException("金鑰不是合法的 Base64: " + e.getMessage(), e);
            }
            try {
                return of(raw, kid);
            } finally {
                // SecretKeySpec 已自行複製一份，raw 只是解碼用的暫存副本；驗證失敗拋例外時也一併清掉。
                Arrays.fill(raw, (byte) 0);
            }
        }

        /**
         * 產生一組新的 AES-256 金鑰，並綁上指定的 kid。
         *
         * <p>Java 9 起預設政策即為 unlimited，256-bit 無須額外安裝 JCE policy 檔。
         */
        public static KeyRef generate(String kid) {
            SecretKey key;
            try {
                KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
                generator.init(KEY_BITS, SECURE_RANDOM);
                key = generator.generateKey();
            } catch (GeneralSecurityException e) {
                throw new CryptoException("無法產生 AES-" + KEY_BITS + " 金鑰", e);
            }
            return new KeyRef(key, kid);
        }

        /**
         * 把金鑰輸出成 URL-safe Base64，方便存進設定檔或環境變數；輸出可直接交給 {@link #ofBase64}。
         * kid 不在輸出內，需另外保存。
         */
        public String keyToBase64() {
            // 建構時已驗證金鑰可匯出，getEncoded() 不會是 null。
            byte[] raw = key.getEncoded();
            try {
                return ENCODER.encodeToString(raw);
            } finally {
                // getEncoded() 回傳的是新陣列；回傳的 Base64 String 則無法清零，交由呼叫端保管。
                Arrays.fill(raw, (byte) 0);
            }
        }

        /** 建構時的金鑰驗證：演算法必須是 AES、長度必須是 256 bits。 */
        private static void requireAes256(SecretKey key) {
            if (!KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
                throw new IllegalArgumentException(
                        "金鑰演算法必須是 " + KEY_ALGORITHM + "，收到: " + key.getAlgorithm());
            }
            byte[] raw = key.getEncoded();
            if (raw == null) {
                // 無法匯出的金鑰量不到長度，視為不合格。
                throw new IllegalArgumentException(
                        "金鑰不支援匯出（getEncoded() 回傳 null），無法驗證長度，例如存放於 HSM 的金鑰");
            }
            try {
                requireKeyLength(raw.length);
            } finally {
                // getEncoded() 回傳的是新陣列，只用來量長度，清掉不影響金鑰本身。
                Arrays.fill(raw, (byte) 0);
            }
        }

        private static void requireKeyLength(int keyBytes) {
            if (keyBytes != KEY_BYTES) {
                throw new IllegalArgumentException(
                        "只接受 AES-" + KEY_BITS + " 金鑰（" + KEY_BYTES + " bytes），收到: "
                                + keyBytes + " bytes");
            }
        }

        /** 刻意覆寫：絕不讓金鑰本身有任何機會被印進 log。 */
        @Override
        public String toString() {
            return "KeyRef[kid=" + kid + ", key=<隱藏>]";
        }
    }

    // ------------------------------------------------------------------
    // 例外
    // ------------------------------------------------------------------

    /** 本 helper 所有失敗的共同父類別，unchecked 讓呼叫端不必被迫 try-catch。 */
    public static class CryptoException extends RuntimeException {
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }

        public CryptoException(String message) {
            super(message);
        }
    }

    /**
     * Token 無法被信任：格式錯、被篡改、或 key 不對。
     *
     * <p>刻意不區分「tag 驗證失敗」與「key 不對」，避免把額外資訊洩漏給攻擊者。
     * 要 debug 請看 {@code getCause()}。
     */
    public static class TokenInvalidException extends CryptoException {
        public TokenInvalidException(String message, Throwable cause) {
            super(message, cause);
        }

        public TokenInvalidException(String message) {
            super(message);
        }
    }

    /**
     * Token 本身是真的（tag 驗證通過），但已經過期。
     *
     * <p>與 {@link TokenInvalidException} 分開，是因為兩者的處置完全不同：
     * 過期該叫使用者重新取得 token，驗證失敗該視為攻擊訊號。
     *
     * <p>注意：解密流程<b>不會</b>自動拋這個例外。它只在應用層主動呼叫
     * {@link Payload#requireNotExpired(Instant)} 時才會發生。
     */
    public static class TokenExpiredException extends CryptoException {
        private final Instant expired;

        public TokenExpiredException(Instant expired) {
            super("token 已於 " + expired + " 過期");
            this.expired = expired;
        }

        /** 回傳 token 的到期時間，方便呼叫端做訊息提示或稽核記錄。 */
        public Instant expired() {
            return expired;
        }
    }

    // ------------------------------------------------------------------
    // 帶時效性的 API（主要入口）
    // ------------------------------------------------------------------

    /**
     * 把 {@link Payload} 加密成一個 URL-safe token。
     *
     * <p>{@code subject} 與 {@code expired} 都在密文裡，沒有解密能力就什麼都看不到。
     * 同一個 payload 連續加密兩次會得到<b>不同</b>的 token，因為 IV 每次重新隨機產生
     * ——這是正確行為，不是 bug。固定輸出等於洩漏「這兩次送的是同一份資料」。
     */
    public static String encryptPayload(Payload payload, KeyRef keyRef) {
        Objects.requireNonNull(payload, "payload 不可為 null");
        byte[] plaintext = serialize(payload);
        try {
            return encrypt(plaintext, keyRef);
        } finally {
            // 明文含 subject，用完立刻清零，縮短它待在 heap 上的時間。
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    /**
     * 解密 token 並解析成 {@link Payload}。
     *
     * <p><b>不檢查時效性。</b>這個方法只保證「token 是用這把金鑰產生的、內容沒被改過」，
     * 至於它是否還在有效期內，由應用層自己決定何時、用哪個時鐘來判斷：
     * <pre>{@code
     * // 一般驗證路徑：解開後立刻要求未過期
     * Payload payload = AesGcmHelper.decryptPayload(token, key)
     *         .requireNotExpired(Instant.now());
     *
     * // 稽核／排錯路徑：過期也要讀出內容
     * Payload stale = AesGcmHelper.decryptPayload(token, key);
     * log.warn("票已於 {} 過期，原持有者 {}", stale.expired(), stale.subject());
     * }</pre>
     *
     * @throws TokenInvalidException token 格式錯、被篡改、或 key 不對
     */
    public static Payload decryptPayload(String token, KeyRef keyRef) {
        byte[] plaintext = decrypt(token, keyRef);
        try {
            return deserialize(plaintext);
        } finally {
            // 明文含 subject，解析成 Payload 後即清零。
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    /** {@code expired(8, big-endian epoch milli) | subject(UTF-8)} */
    private static byte[] serialize(Payload payload) {
        byte[] subject = payload.subject().getBytes(StandardCharsets.UTF_8);
        // expired 固定長、subject 吃剩下全部，所以不需要分隔符，
        // subject 內含任何字元都不會造成解析歧義。
        return ByteBuffer.allocate(EXPIRED_FIELD_LENGTH + subject.length)
                .putLong(payload.expired().toEpochMilli())
                .put(subject)
                .array();
    }

    private static Payload deserialize(byte[] plaintext) {
        if (plaintext.length < EXPIRED_FIELD_LENGTH) {
            // tag 驗證已通過卻長度不對，代表是用同一把 key 加密的「別種格式」資料。
            throw new TokenInvalidException("解密成功但 payload 結構不符，長度僅 " + plaintext.length + " bytes");
        }
        ByteBuffer buffer = ByteBuffer.wrap(plaintext);
        Instant expired = Instant.ofEpochMilli(buffer.getLong());
        byte[] subject = new byte[plaintext.length - EXPIRED_FIELD_LENGTH];
        buffer.get(subject);
        try {
            return new Payload(new String(subject, StandardCharsets.UTF_8), expired);
        } finally {
            // new String 已複製內容，原始 bytes 可清。
            Arrays.fill(subject, (byte) 0);
        }
    }

    // ------------------------------------------------------------------
    // 底層 API（不含時效性，只做 AEAD）
    // ------------------------------------------------------------------

    /**
     * 加密任意 bytes，回傳 URL-safe token。不含任何時效性語意。
     *
     * <p>字串請自行 {@code s.getBytes(StandardCharsets.UTF_8)}；
     * 指定編碼是刻意的，依賴平台預設編碼會在不同機器上解出亂碼。
     */
    public static String encrypt(byte[] plaintext, KeyRef keyRef) {
        Objects.requireNonNull(plaintext, "plaintext 不可為 null");
        Objects.requireNonNull(keyRef, "keyRef 不可為 null");

        byte[] iv = new byte[IV_LENGTH];
        SECURE_RANDOM.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keyRef.key(),
                    new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            cipher.updateAAD(aad(keyRef.kid()));
            byte[] sealed = cipher.doFinal(plaintext); // sealed = ciphertext | tag

            return ENCODER.encodeToString(
                    ByteBuffer.allocate(1 + IV_LENGTH + sealed.length)
                            .put(VERSION)
                            .put(iv)
                            .put(sealed)
                            .array());
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES/GCM 加密失敗: " + e.getMessage(), e);
        }
    }

    /**
     * 驗證並解密 token。
     *
     * <p>回傳值只有在 {@code doFinal} 成功（即 tag 驗證通過）後才存在；
     * GCM 的認證發生在 {@code doFinal}，所以在那之前拿到的任何 bytes 都不可信任。
     *
     * @throws TokenInvalidException 格式錯、被篡改、或 key 不對
     */
    public static byte[] decrypt(String token, KeyRef keyRef) {
        Objects.requireNonNull(token, "token 不可為 null");
        Objects.requireNonNull(keyRef, "keyRef 不可為 null");

        byte[] raw;
        try {
            raw = DECODER.decode(token);
        } catch (IllegalArgumentException e) {
            throw new TokenInvalidException("token 不是合法的 Base64URL", e);
        }

        if (raw.length < MIN_TOKEN_BYTES) {
            throw new TokenInvalidException(
                    "token 長度不足，至少需 " + MIN_TOKEN_BYTES + " bytes，實際 " + raw.length);
        }
        if (raw[0] != VERSION) {
            throw new TokenInvalidException("不支援的 token 版號: " + raw[0]);
        }

        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keyRef.key(),
                    new GCMParameterSpec(TAG_LENGTH_BITS, raw, 1, IV_LENGTH));
            cipher.updateAAD(aad(keyRef.kid()));
            return cipher.doFinal(raw, 1 + IV_LENGTH, raw.length - 1 - IV_LENGTH);
        } catch (GeneralSecurityException e) {
            // 統一訊息：不告訴對方是金鑰錯、kid 錯、還是內容被改，少給攻擊者一個 oracle。
            throw new TokenInvalidException("token 驗證失敗（金鑰或 kid 不符，或內容已被篡改）", e);
        }
    }

    /**
     * 組出 AAD：{@code VERSION(1 byte) || kid 的 UTF-8 bytes}。
     *
     * <p>AAD 的唯一要求是「加解密兩端算出完全相同的 byte 序列」。版號固定佔第一個 byte，
     * 所以 (版號, kid) 的不同組合不會產生相同的 AAD——這也是 {@link KeyRef} 禁止空 kid
     * 的原因：空 kid 會讓 AAD 退化成只剩版號。
     *
     * <p>版號納入 AAD 是為格式演進預留 domain separation：日後若有 v2，
     * 攻擊者無法把 v2 的密文搬到 v1 的 header 底下重放。
     */
    private static byte[] aad(String kid) {
        byte[] kidBytes = kid.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(1 + kidBytes.length)
                .put(VERSION)
                .put(kidBytes)
                .array();
    }
}
