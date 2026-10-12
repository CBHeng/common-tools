package io.github.cboheng.commontools.crypto;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.cboheng.commontools.crypto.AesGcmHelper.CryptoException;
import io.github.cboheng.commontools.crypto.AesGcmHelper.KeyRef;
import io.github.cboheng.commontools.crypto.AesGcmHelper.Payload;
import io.github.cboheng.commontools.crypto.AesGcmHelper.TokenExpiredException;
import io.github.cboheng.commontools.crypto.AesGcmHelper.TokenInvalidException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.IntStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("AesGcmHelper：AES/GCM/NoPadding + 時效性")
class AesGcmHelperTest {

    private static final String KID = "test-kid-v1";

    private SecretKey key;
    private KeyRef keyRef;

    @BeforeEach
    void setUp() {
        keyRef = KeyRef.generate(KID);
        key = keyRef.key();
    }

    // ==================================================================
    @Nested
    @DisplayName("主題 1：基本往返（round-trip）")
    class RoundTrip {

        @Test
        @DisplayName("encryptPayload → decryptPayload 可完整還原 subject 與 expired")
        void payloadRoundTrip() {
            Payload original = Payload.validFor("user-42", Duration.ofMinutes(15));

            Payload restored = AesGcmHelper.decryptPayload(
                    AesGcmHelper.encryptPayload(original, keyRef), keyRef);

            assertAll(
                    () -> assertEquals(original.subject(), restored.subject()),
                    () -> assertEquals(original.expired(), restored.expired()),
                    () -> assertEquals(original, restored, "record 應整體相等"));
        }

        @ParameterizedTest(name = "subject = \"{0}\"")
        @DisplayName("subject 支援中文、emoji、空字串、換行與分隔符號")
        @ValueSource(strings = {
                "",
                "simple-ascii",
                "中文使用者名稱",
                "emoji-🔐🎋",
                "a\nb\tc\u0000d",
                "has|pipe:and,comma",
                "   leading and trailing   "
        })
        void subjectSurvivesAnyCharacter(String subject) {
            Payload original = new Payload(subject, Instant.now().plusSeconds(60));

            Payload restored = AesGcmHelper.decryptPayload(
                    AesGcmHelper.encryptPayload(original, keyRef), keyRef);

            assertEquals(subject, restored.subject());
        }

        @Test
        @DisplayName("subject 很長（10,000 字）也不會被截斷")
        void longSubject() {
            String subject = "x".repeat(10_000);
            Payload original = new Payload(subject, Instant.now().plusSeconds(60));

            Payload restored = AesGcmHelper.decryptPayload(
                    AesGcmHelper.encryptPayload(original, keyRef), keyRef);

            assertEquals(10_000, restored.subject().length());
            assertEquals(subject, restored.subject());
        }

        @Test
        @DisplayName("底層 encrypt/decrypt 可還原任意 bytes")
        void rawBytesRoundTrip() {
            byte[] plaintext = new byte[1024];
            new SecureRandom().nextBytes(plaintext);

            byte[] restored = AesGcmHelper.decrypt(AesGcmHelper.encrypt(plaintext, keyRef), keyRef);

            assertArrayEquals(plaintext, restored);
        }

        @Test
        @DisplayName("空 byte 陣列也能加解密（GCM 允許空明文，tag 仍存在）")
        void emptyPlaintext() {
            String token = AesGcmHelper.encrypt(new byte[0], keyRef);

            assertArrayEquals(new byte[0], AesGcmHelper.decrypt(token, keyRef));
        }

        @Test
        @DisplayName("token 是 URL-safe 的：不含 + / = 三種字元")
        void tokenIsUrlSafe() {
            String token = AesGcmHelper.encryptPayload(
                    Payload.validFor("user-42", Duration.ofMinutes(5)), keyRef);

            assertAll(
                    () -> assertFalse(token.contains("+"), "不該含 +"),
                    () -> assertFalse(token.contains("/"), "不該含 /"),
                    () -> assertFalse(token.contains("="), "不該含 padding ="));
        }
    }

    // ==================================================================
    @Nested
    @DisplayName("主題 2：時效性（判斷權在應用層）")
    class Expiry {

        @Test
        @DisplayName("decryptPayload 不檢查時效：已過期的 token 照樣解得開，不拋例外")
        void decryptPayloadDoesNotCheckExpiry() {
            Instant expired = Instant.now().minus(Duration.ofDays(30));
            String token = AesGcmHelper.encryptPayload(new Payload("user-42", expired), keyRef);

            // 這一行若拋例外，代表 helper 又把時效判斷搶回去做了。
            Payload payload = AesGcmHelper.decryptPayload(token, keyRef);

            assertAll(
                    () -> assertEquals("user-42", payload.subject(), "過期也要讀得出內容，供稽核用"),
                    () -> assertEquals(expired.truncatedTo(ChronoUnit.MILLIS), payload.expired()),
                    () -> assertTrue(payload.isExpired(Instant.now()), "但它確實已經過期了"));
        }

        @Test
        @DisplayName("requireNotExpired：未過期時原封不動回傳自己，可直接串接")
        void requireNotExpiredPassesThrough() {
            String token = AesGcmHelper.encryptPayload(
                    Payload.validFor("user-42", Duration.ofMinutes(10)), keyRef);

            Payload payload = AesGcmHelper.decryptPayload(token, keyRef)
                    .requireNotExpired(Instant.now());

            assertEquals("user-42", payload.subject());
        }

        @Test
        @DisplayName("requireNotExpired：已過期時拋 TokenExpiredException 並帶出到期時間")
        void requireNotExpiredThrowsWhenStale() {
            Instant expired = Instant.now().minusSeconds(1);
            String token = AesGcmHelper.encryptPayload(new Payload("user-42", expired), keyRef);
            Payload payload = AesGcmHelper.decryptPayload(token, keyRef);
            Instant now = Instant.now();

            TokenExpiredException ex = assertThrows(TokenExpiredException.class,
                    () -> payload.requireNotExpired(now));

            assertEquals(expired.truncatedTo(ChronoUnit.MILLIS), ex.expired());
        }

        @Test
        @DisplayName("「現在」由呼叫端傳入，所以時間可以被凍結——這是把時鐘交給應用層的實質好處")
        void nowIsInjectedByCaller() {
            Payload payload = new Payload("user-42", Instant.parse("2030-01-01T00:00:00Z"));

            assertAll(
                    () -> assertEquals(payload,
                            payload.requireNotExpired(Instant.parse("2029-12-31T23:59:59.999Z")),
                            "到期前 1 毫秒仍有效"),
                    () -> assertThrows(TokenExpiredException.class,
                            () -> payload.requireNotExpired(Instant.parse("2030-01-01T00:00:00Z")),
                            "到期的那一瞬間即失效"),
                    () -> assertThrows(TokenExpiredException.class,
                            () -> payload.requireNotExpired(Instant.parse("2030-01-01T00:00:00.001Z"))));
        }

        @Test
        @DisplayName("到期的那一瞬間（now == expired）即視為過期，不給寬限")
        void expiresAtTheExactInstant() {
            Payload payload = new Payload("user-42", Instant.parse("2030-01-01T00:00:00Z"));

            assertAll(
                    () -> assertTrue(payload.isExpired(payload.expired()), "now == expired 應算過期"),
                    () -> assertTrue(payload.isExpired(payload.expired().plusMillis(1))),
                    () -> assertFalse(payload.isExpired(payload.expired().minusMillis(1))));
        }

        @Test
        @DisplayName("validFor 以「現在 + ttl」計算到期時間")
        void validForComputesDeadline() {
            Instant before = Instant.now();
            Payload payload = Payload.validFor("user-42", Duration.ofMinutes(30));
            Instant after = Instant.now();

            assertAll(
                    () -> assertFalse(payload.expired().isBefore(
                            before.plus(Duration.ofMinutes(30)).truncatedTo(ChronoUnit.MILLIS))),
                    () -> assertFalse(payload.expired().isAfter(after.plus(Duration.ofMinutes(30)))));
        }

        @ParameterizedTest(name = "ttl = {0} 秒")
        @DisplayName("validFor 拒絕零與負的 ttl（這種 token 一出生就死，必定是呼叫端寫錯）")
        @ValueSource(longs = { 0L, -1L, -3600L })
        void validForRejectsNonPositiveTtl(long seconds) {
            assertThrows(IllegalArgumentException.class,
                    () -> Payload.validFor("user-42", Duration.ofSeconds(seconds)));
        }

        @Test
        @DisplayName("expired 的奈秒在建構時就被截到毫秒，所以 round-trip 後必然相等")
        void nanosAreTruncatedAtConstruction() {
            Instant withNanos = Instant.parse("2030-01-01T00:00:00.123456789Z");

            Payload payload = new Payload("user-42", withNanos);
            Payload restored = AesGcmHelper.decryptPayload(
                    AesGcmHelper.encryptPayload(payload, keyRef), keyRef);

            assertAll(
                    () -> assertEquals(Instant.parse("2030-01-01T00:00:00.123Z"), payload.expired()),
                    () -> assertEquals(payload.expired(), restored.expired(),
                            "若未在建構時截斷，這裡會因奈秒遺失而失敗"));
        }

        @Test
        @DisplayName("expired 超出 epoch milli 可表示範圍時，建構時就擋下來")
        void rejectsUnrepresentableInstant() {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> new Payload("user-42", Instant.MAX));

            assertTrue(ex.getMessage().contains("epoch milli"));
        }
    }

    // ==================================================================
    @Nested
    @DisplayName("主題 3：時戳與內容確實藏在密文裡")
    class NothingLeaksInPlaintext {

        @Test
        @DisplayName("token 的位元組裡找不到 expired 的明文時戳")
        void expiredTimestampIsNotVisible() {
            Instant expired = Instant.parse("2030-06-15T08:30:00Z");
            String token = AesGcmHelper.encryptPayload(new Payload("user-42", expired), keyRef);

            byte[] raw = Base64.getUrlDecoder().decode(token);
            byte[] timestampBytes = ByteBuffer.allocate(Long.BYTES)
                    .putLong(expired.toEpochMilli()).array();

            assertEquals(-1, indexOf(raw, timestampBytes),
                    "時戳若出現在 token 裡，代表它沒被加密");
        }

        @Test
        @DisplayName("token 的位元組裡找不到 subject 的明文內容")
        void subjectIsNotVisible() {
            String subject = "highly-identifiable-subject-value";
            String token = AesGcmHelper.encryptPayload(
                    new Payload(subject, Instant.now().plusSeconds(60)), keyRef);

            byte[] raw = Base64.getUrlDecoder().decode(token);

            assertEquals(-1, indexOf(raw, subject.getBytes(UTF_8)));
        }

        @Test
        @DisplayName("token 結構符合 version(1) + IV(12) + ciphertext + tag(16)")
        void tokenLayout() {
            byte[] plaintext = new byte[100];
            byte[] raw = Base64.getUrlDecoder().decode(AesGcmHelper.encrypt(plaintext, keyRef));

            assertAll(
                    () -> assertEquals(0x01, raw[0], "第 1 byte 應為版號"),
                    () -> assertEquals(1 + 12 + 100 + 16, raw.length,
                            "總長 = 版號 + IV + 明文長度 + tag"));
        }
    }

    // ==================================================================
    @Nested
    @DisplayName("主題 4：完整性 — 任何篡改都必須被擋下")
    class Integrity {

        @Test
        @DisplayName("翻轉 token 中「任何一個 byte」都會導致驗證失敗")
        void flippingAnyByteIsDetected() {
            String token = AesGcmHelper.encryptPayload(
                    Payload.validFor("user-42", Duration.ofMinutes(10)), keyRef);
            byte[] raw = Base64.getUrlDecoder().decode(token);

            for (int i = 0; i < raw.length; i++) {
                byte[] tampered = raw.clone();
                tampered[i] ^= 0x01; // 只翻最低位，是最小幅度的篡改
                String tamperedToken = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(tampered);

                int index = i;
                assertThrows(TokenInvalidException.class,
                        () -> AesGcmHelper.decryptPayload(tamperedToken, keyRef),
                        () -> "第 " + index + " byte 被改動卻沒被偵測到");
            }
        }

        @Test
        @DisplayName("用錯的金鑰解密會失敗，而且不會洩漏是金鑰錯還是內容被改")
        void wrongKeyFails() {
            String token = AesGcmHelper.encryptPayload(
                    Payload.validFor("user-42", Duration.ofMinutes(10)), keyRef);
            KeyRef otherKey = KeyRef.generate(KID);

            TokenInvalidException ex = assertThrows(TokenInvalidException.class,
                    () -> AesGcmHelper.decryptPayload(token, otherKey));

            assertFalse(ex.getMessage().toLowerCase().contains("tag"),
                    "錯誤訊息不應透露 tag 層級的細節");
        }

        @Test
        @DisplayName("AAD 真的被納入認證：少餵 AAD 所產生的密文解不開")
        void aadIsActuallyAuthenticated() throws Exception {
            // 繞過 helper，直接用 JCE 以相同 key 加密，但「不」餵 AAD。
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] sealed = cipher.doFinal("payload".getBytes(UTF_8));

            String tokenWithoutAad = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    ByteBuffer.allocate(1 + iv.length + sealed.length)
                            .put((byte) 0x01).put(iv).put(sealed).array());

            // helper 解密時會餵 AAD，與加密時不一致 → 必須失敗。
            assertThrows(TokenInvalidException.class,
                    () -> AesGcmHelper.decrypt(tokenWithoutAad, keyRef));
        }

        @Test
        @DisplayName("改掉版號會被拒絕（不會拿舊版解析邏輯去硬解）")
        void unknownVersionIsRejected() {
            String token = AesGcmHelper.encrypt("payload".getBytes(UTF_8), keyRef);
            byte[] raw = Base64.getUrlDecoder().decode(token);
            raw[0] = 0x02;

            TokenInvalidException ex = assertThrows(TokenInvalidException.class,
                    () -> AesGcmHelper.decrypt(
                            Base64.getUrlEncoder().withoutPadding().encodeToString(raw), keyRef));

            assertTrue(ex.getMessage().contains("版號"));
        }

        @ParameterizedTest(name = "輸入 = \"{0}\"")
        @DisplayName("格式不成立的 token 一律拒絕，不會拋出意料外的例外")
        @ValueSource(strings = {
                "",
                "a",
                "not-a-valid-token",
                "!!!not-base64!!!",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        })
        void malformedTokensAreRejected(String token) {
            assertThrows(TokenInvalidException.class,
                    () -> AesGcmHelper.decryptPayload(token, keyRef));
        }

        @Test
        @DisplayName("被截斷的 token（tag 不完整）會被拒絕")
        void truncatedTokenIsRejected() {
            String token = AesGcmHelper.encryptPayload(
                    Payload.validFor("user-42", Duration.ofMinutes(10)), keyRef);
            byte[] raw = Base64.getUrlDecoder().decode(token);
            byte[] truncated = Arrays.copyOf(raw, raw.length - 4);

            assertThrows(TokenInvalidException.class,
                    () -> AesGcmHelper.decryptPayload(
                            Base64.getUrlEncoder().withoutPadding().encodeToString(truncated), keyRef));
        }

        @Test
        @DisplayName("用同一把 key 加密的「別種格式」資料，解密後會因結構不符被拒絕")
        void wellEncryptedButWrongStructure() {
            // tag 驗證會通過（確實是這把 key 加的），但只有 3 bytes，湊不出 8 bytes 的 expired。
            String token = AesGcmHelper.encrypt(new byte[] { 1, 2, 3 }, keyRef);

            assertThrows(TokenInvalidException.class,
                    () -> AesGcmHelper.decryptPayload(token, keyRef));
        }
    }

    // ==================================================================
    @Nested
    @DisplayName("主題 5：IV 隨機性 — 同樣的輸入不該產生同樣的輸出")
    class IvRandomness {

        @Test
        @DisplayName("同一個 payload 加密兩次會得到不同的 token")
        void sameInputProducesDifferentTokens() {
            Payload payload = new Payload("user-42", Instant.parse("2030-01-01T00:00:00Z"));

            String first = AesGcmHelper.encryptPayload(payload, keyRef);
            String second = AesGcmHelper.encryptPayload(payload, keyRef);

            assertAll(
                    () -> assertNotEquals(first, second, "固定輸出會洩漏「兩次送的是同一份資料」"),
                    () -> assertEquals(payload, AesGcmHelper.decryptPayload(first, keyRef)),
                    () -> assertEquals(payload, AesGcmHelper.decryptPayload(second, keyRef)));
        }

        @Test
        @DisplayName("連續加密 2,000 次，IV 不得重複（重複即代表 GCM 安全性崩潰）")
        void ivNeverRepeats() {
            int rounds = 2_000;
            Set<String> seenIvs = new HashSet<>();

            for (int i = 0; i < rounds; i++) {
                byte[] raw = Base64.getUrlDecoder().decode(
                        AesGcmHelper.encrypt(new byte[0], keyRef));
                seenIvs.add(Base64.getEncoder().encodeToString(
                        Arrays.copyOfRange(raw, 1, 13)));
            }

            assertEquals(rounds, seenIvs.size(), "出現重複的 IV");
        }
    }

    // ==================================================================
    @Nested
    @DisplayName("主題 6：金鑰工具")
    class KeyUtilities {

        @Test
        @DisplayName("KeyRef.generate 給 AES-256，並綁上指定的 kid")
        void generatedKeyIs256Bits() {
            KeyRef generated = KeyRef.generate("2026-10");

            assertAll(
                    () -> assertEquals(32, generated.key().getEncoded().length),
                    () -> assertEquals("2026-10", generated.kid()));
        }

        @ParameterizedTest(name = "{0} bytes")
        @DisplayName("KeyRef.of 只接受 32 bytes（AES-128 / 192 也拒絕）")
        @ValueSource(ints = { 0, 8, 16, 24, 31, 33, 64 })
        void ofRejectsWrongLength(int byteLength) {
            assertThrows(IllegalArgumentException.class,
                    () -> KeyRef.of(new byte[byteLength], KID));
        }

        @Test
        @DisplayName("KeyRef.of 複製傳入的 bytes：之後清零原陣列，金鑰照樣可用")
        void ofCopiesRawBytes() {
            byte[] raw = key.getEncoded();
            byte[] expected = raw.clone();
            KeyRef fromRaw = KeyRef.of(raw, KID);
            String token = AesGcmHelper.encrypt(new byte[] { 1, 2, 3 }, keyRef);

            Arrays.fill(raw, (byte) 0);

            assertAll(
                    () -> assertArrayEquals(expected, fromRaw.key().getEncoded()),
                    () -> assertArrayEquals(new byte[] { 1, 2, 3 }, AesGcmHelper.decrypt(token, fromRaw)));
        }

        @Test
        @DisplayName("KeyRef.ofBase64 同時吃標準 Base64（+ /）與 URL-safe（- _）兩種字元表")
        void acceptsBothBase64Alphabets() {
            byte[] raw = new byte[32];
            new SecureRandom().nextBytes(raw);
            String standard = Base64.getEncoder().encodeToString(raw);
            String urlSafe = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

            assertAll(
                    () -> assertArrayEquals(raw, KeyRef.ofBase64(standard, KID).key().getEncoded()),
                    () -> assertArrayEquals(raw, KeyRef.ofBase64(urlSafe, KID).key().getEncoded()));
        }

        @ParameterizedTest(name = "{0} bytes")
        @DisplayName("KeyRef 建構時就拒絕非 AES-256 的金鑰，不等到加解密")
        @ValueSource(ints = { 16, 24, 31, 33 })
        void keyRefRejectsWrongKeyLength(int byteLength) {
            SecretKey weak = new SecretKeySpec(new byte[byteLength], "AES");

            assertThrows(IllegalArgumentException.class, () -> new KeyRef(weak, KID));
        }

        @Test
        @DisplayName("KeyRef 拒絕演算法不是 AES 的金鑰")
        void keyRefRejectsNonAesKey() {
            SecretKey hmac = new SecretKeySpec(new byte[32], "HmacSHA256");

            assertThrows(IllegalArgumentException.class, () -> new KeyRef(hmac, KID));
        }

        @Test
        @DisplayName("KeyRef 拒絕無法匯出的金鑰（量不到長度）")
        void keyRefRejectsNonExportableKey() {
            SecretKey opaque = new SecretKey() {
                @Override public String getAlgorithm() { return "AES"; }
                @Override public String getFormat() { return null; }
                @Override public byte[] getEncoded() { return null; }
            };

            assertThrows(IllegalArgumentException.class, () -> new KeyRef(opaque, KID));
        }

        @Test
        @DisplayName("KeyRef.ofBase64 遇到非 Base64 內容時拋 CryptoException")
        void rejectsGarbageBase64() {
            assertThrows(CryptoException.class, () -> KeyRef.ofBase64("!!!!", KID));
        }
    }

    // ==================================================================
    @Nested
    @DisplayName("主題 7：kid 與金鑰綁定")
    class KeyIdBinding {

        @Test
        @DisplayName("同一把金鑰、不同 kid → 解不開（kid 確實被綁進認證範圍）")
        void sameKeyDifferentKidFails() {
            String token = AesGcmHelper.encryptPayload(
                    Payload.validFor("user-42", Duration.ofMinutes(10)), keyRef);
            KeyRef otherKid = new KeyRef(key, "another-kid");

            assertThrows(TokenInvalidException.class,
                    () -> AesGcmHelper.decryptPayload(token, otherKid));
        }

        @Test
        @DisplayName("同一個 kid、不同金鑰 → 解不開")
        void sameKidDifferentKeyFails() {
            String token = AesGcmHelper.encryptPayload(
                    Payload.validFor("user-42", Duration.ofMinutes(10)), keyRef);
            KeyRef otherKey = KeyRef.generate(KID);

            assertThrows(TokenInvalidException.class,
                    () -> AesGcmHelper.decryptPayload(token, otherKey));
        }

        @Test
        @DisplayName("kid 大小寫敏感：\"V1\" 解不開 \"v1\" 發的 token")
        void kidIsCaseSensitive() {
            String token = AesGcmHelper.encryptPayload(
                    Payload.validFor("user-42", Duration.ofMinutes(10)), new KeyRef(key, "v1"));

            assertThrows(TokenInvalidException.class,
                    () -> AesGcmHelper.decryptPayload(token, new KeyRef(key, "V1")));
        }

        @Test
        @DisplayName("改掉 kid 等於全面撤銷：舊 token 全部失效，而且不必換金鑰")
        void rotatingKidRevokesEverything() {
            KeyRef before = new KeyRef(key, "2026-10");
            KeyRef after = new KeyRef(key, "2026-11");   // 同一把金鑰，只換 kid

            List<String> issued = IntStream.range(0, 5)
                    .mapToObj(i -> AesGcmHelper.encryptPayload(
                            Payload.validFor("user-" + i, Duration.ofHours(1)), before))
                    .toList();

            assertAll(
                    () -> assertDoesNotThrow(
                            () -> issued.forEach(t -> AesGcmHelper.decryptPayload(t, before)),
                            "輪替前，舊 kid 當然解得開"),
                    () -> issued.forEach(t -> assertThrows(TokenInvalidException.class,
                            () -> AesGcmHelper.decryptPayload(t, after),
                            "換了 kid 之後，同一把金鑰也必須解不開")));
        }

        @Test
        @DisplayName("kid 不會出現在 token 裡（它在 AAD，不在 token）")
        void kidIsNotPresentInToken() {
            String kid = "highly-identifiable-kid-value";
            String token = AesGcmHelper.encryptPayload(
                    Payload.validFor("user-42", Duration.ofMinutes(10)), new KeyRef(key, kid));

            byte[] raw = Base64.getUrlDecoder().decode(token);

            assertEquals(-1, indexOf(raw, kid.getBytes(UTF_8)),
                    "kid 若出現在 token 裡，就不是「只餵 AAD」的設計了");
        }

        @Test
        @DisplayName("token 長度完全不受 kid 長度影響——這是 kid 不在 token 裡的直接證據")
        void tokenLengthIsIndependentOfKidLength() {
            Payload payload = new Payload("user-42", Instant.parse("2030-01-01T00:00:00Z"));

            String withShortKid = AesGcmHelper.encryptPayload(payload, new KeyRef(key, "v1"));
            String withLongKid = AesGcmHelper.encryptPayload(payload,
                    new KeyRef(key, "a-very-long-key-identifier-for-2026-10-rotation-cycle"));

            assertEquals(withShortKid.length(), withLongKid.length());
        }

        @ParameterizedTest(name = "kid = \"{0}\"")
        @DisplayName("kid 支援非 ASCII 內容，且仍能正確往返")
        @ValueSource(strings = { "v1", "2026-10", "中文金鑰代號", "kid-with-emoji-\uD83D\uDD11",
                "550e8400-e29b-41d4-a716-446655440000" })
        void kidSupportsAnyNonEmptyString(String kid) {
            KeyRef ref = new KeyRef(key, kid);
            Payload payload = Payload.validFor("user-42", Duration.ofMinutes(10));

            assertEquals(payload, AesGcmHelper.decryptPayload(
                    AesGcmHelper.encryptPayload(payload, ref), ref));
        }

        @Test
        @DisplayName("kid 不可為空字串（空 kid 會讓 AAD 退化成只剩版號）")
        void emptyKidIsRejected() {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> new KeyRef(key, ""));

            assertTrue(ex.getMessage().contains("不可為空"));
        }

        @Test
        @DisplayName("kid 與 key 都不可為 null")
        void nullsAreRejected() {
            assertAll(
                    () -> assertThrows(NullPointerException.class, () -> new KeyRef(null, KID)),
                    () -> assertThrows(NullPointerException.class, () -> new KeyRef(key, null)));
        }

        @Test
        @DisplayName("kid 長度上限 256 bytes：剛好 256 可以，257 被拒")
        void kidLengthLimit() {
            assertAll(
                    () -> assertDoesNotThrow(() -> new KeyRef(key, "k".repeat(256))),
                    () -> assertThrows(IllegalArgumentException.class,
                            () -> new KeyRef(key, "k".repeat(257))));
        }

        @Test
        @DisplayName("上限是以 UTF-8 byte 數計算，不是字元數")
        void kidLimitCountsBytesNotChars() {
            String threeByteChar = "中";                       // UTF-8 佔 3 bytes
            assertEquals(3, threeByteChar.getBytes(UTF_8).length);

            assertAll(
                    () -> assertDoesNotThrow(() -> new KeyRef(key, threeByteChar.repeat(85))),
                    () -> assertThrows(IllegalArgumentException.class,
                            () -> new KeyRef(key, threeByteChar.repeat(86))));
        }

        @Test
        @DisplayName("keyRef.keyToBase64 → KeyRef.ofBase64 可往返，且還原的 KeyRef 解得開原本的 token")
        void ofBase64Equivalence() {
            String base64 = keyRef.keyToBase64();
            KeyRef fromBase64 = KeyRef.ofBase64(base64, KID);
            Payload payload = Payload.validFor("user-42", Duration.ofMinutes(10));

            String token = AesGcmHelper.encryptPayload(payload, keyRef);

            assertAll(
                    () -> assertEquals(KID, fromBase64.kid()),
                    () -> assertArrayEquals(key.getEncoded(), fromBase64.key().getEncoded()),
                    () -> assertEquals(payload, AesGcmHelper.decryptPayload(token, fromBase64)));
        }

        @Test
        @DisplayName("KeyRef.toString 不洩漏金鑰內容")
        void toStringHidesKey() {
            String rendered = keyRef.toString();

            assertAll(
                    () -> assertFalse(rendered.contains(keyRef.keyToBase64())),
                    () -> assertTrue(rendered.contains(KID), "kid 可以顯示，它本來就不是秘密"),
                    () -> assertTrue(rendered.contains("隱藏")));
        }
    }

    // ==================================================================
    @Nested
    @DisplayName("主題 8：參數驗證")
    class ArgumentValidation {

        @Test
        @DisplayName("null 參數一律在進入加密流程前就拋 NullPointerException")
        void nullArgumentsAreRejected() {
            String token = AesGcmHelper.encrypt(new byte[1], keyRef);
            Payload payload = Payload.validFor("user-42", Duration.ofMinutes(5));

            assertAll(
                    () -> assertThrows(NullPointerException.class,
                            () -> AesGcmHelper.encryptPayload(null, keyRef)),
                    () -> assertThrows(NullPointerException.class,
                            () -> AesGcmHelper.encryptPayload(payload, null)),
                    () -> assertThrows(NullPointerException.class,
                            () -> AesGcmHelper.decryptPayload(null, keyRef)),
                    () -> assertThrows(NullPointerException.class,
                            () -> AesGcmHelper.decryptPayload(token, null)),
                    () -> assertThrows(NullPointerException.class,
                            () -> AesGcmHelper.encrypt(null, keyRef)),
                    () -> assertThrows(NullPointerException.class,
                            () -> AesGcmHelper.decrypt(null, keyRef)),
                    () -> assertThrows(NullPointerException.class,
                            () -> KeyRef.of(null, KID)),
                    () -> assertThrows(NullPointerException.class,
                            () -> KeyRef.ofBase64(null, KID)),
                    () -> assertThrows(NullPointerException.class,
                            () -> KeyRef.generate(null)));
        }

        @Test
        @DisplayName("Payload 不接受 null 的 subject 或 expired")
        void payloadRejectsNulls() {
            assertAll(
                    () -> assertThrows(NullPointerException.class,
                            () -> new Payload(null, Instant.now())),
                    () -> assertThrows(NullPointerException.class,
                            () -> new Payload("user-42", null)),
                    () -> assertThrows(NullPointerException.class,
                            () -> Payload.validFor("user-42", null)),
                    () -> assertThrows(NullPointerException.class,
                            () -> new Payload("user-42", Instant.now()).isExpired(null)));
        }

        @Test
        @DisplayName("Payload.toString 不會把 subject 內容寫出去（避免誤入 log）")
        void toStringHidesSubject() {
            String secret = "0912345678";
            String rendered = new Payload(secret, Instant.now()).toString();

            assertAll(
                    () -> assertFalse(rendered.contains(secret), "subject 不該出現在 toString"),
                    () -> assertTrue(rendered.contains("已隱藏")));
        }
    }

    // ==================================================================
    @Nested
    @DisplayName("主題 9：執行緒安全")
    class ThreadSafety {

        @Test
        @DisplayName("多執行緒並行加解密 2,000 次不出錯，且結果全部正確")
        void concurrentUseIsSafe() {
            int rounds = 2_000;
            ConcurrentLinkedQueue<String> failures = new ConcurrentLinkedQueue<>();

            Set<String> tokens = Collections.synchronizedSet(new HashSet<>());
            IntStream.range(0, rounds).parallel().forEach(i -> {
                try {
                    Payload payload = new Payload("user-" + i, Instant.now().plusSeconds(600));
                    String token = AesGcmHelper.encryptPayload(payload, keyRef);
                    tokens.add(token);
                    Payload restored = AesGcmHelper.decryptPayload(token, keyRef);
                    if (!payload.equals(restored)) {
                        failures.add("第 " + i + " 筆內容不符");
                    }
                } catch (RuntimeException e) {
                    failures.add("第 " + i + " 筆拋出 " + e);
                }
            });

            assertAll(
                    () -> assertTrue(failures.isEmpty(), () -> "並行失敗: " + failures),
                    () -> assertEquals(rounds, tokens.size(), "並行下仍不得產生重複 token"));
        }
    }

    // ==================================================================
    @Nested
    @DisplayName("主題 10：工具類別慣例")
    class HelperConventions {

        @Test
        @DisplayName("AesGcmHelper 不可被實例化")
        void cannotBeInstantiated() throws Exception {
            Constructor<AesGcmHelper> constructor = AesGcmHelper.class.getDeclaredConstructor();
            constructor.setAccessible(true);

            InvocationTargetException wrapper =
                    assertThrows(InvocationTargetException.class, constructor::newInstance);

            assertTrue(wrapper.getCause() instanceof AssertionError);
        }
    }

    // ------------------------------------------------------------------
    /** 回傳 needle 在 haystack 中第一次出現的位置，找不到回傳 -1。 */
    private static int indexOf(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || needle.length > haystack.length) {
            return -1;
        }
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
