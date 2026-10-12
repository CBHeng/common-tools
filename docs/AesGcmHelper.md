# AesGcmHelper

AES/GCM/NoPadding 認證加密，外加時效性包裝與金鑰識別碼（kid）綁定。
全 `static` method、零外部依賴、單一檔案可直接 copy 進既有專案。

> 專案總覽與其他工具見 [../README.md](../README.md)。
> 原始碼：[`AesGcmHelper.java`](../src/main/java/io/github/cboheng/commontools/crypto/AesGcmHelper.java)　測試：[`AesGcmHelperTest.java`](../src/test/java/io/github/cboheng/commontools/crypto/AesGcmHelperTest.java)（78 tests）

本文件可以跳著看：

| 章節 | 給誰看 |
|---|---|
| [一、它解決什麼問題](#一它解決什麼問題) | 先判斷這個工具適不適合你的情境 |
| [二、60 秒上手](#二60-秒上手) | 只想趕快用起來 |
| [三、API 一覽](#三api-一覽) | 查簽名、看真實輸出長什麼樣 |
| [四、實戰場景](#四實戰場景) | 一般加解密、時效性加解密各一個範例 |
| [五、加密方式細節](#五加密方式細節) | 想知道底下發生什麼事、要跟資安審查解釋 |
| [六、安全性細節](#六安全性細節) | **上線前請務必看完「不防什麼」那一節** |
| [七、時效性細節](#七時效性細節) | 要處理時鐘偏移、撤銷、重放 |
| [八、常見錯誤用法](#八常見錯誤用法) | Code review 用的對照表 |
| [九、設計決策與取捨](#九設計決策與取捨) | 想知道為什麼這樣設計、代價是什麼 |
| [十、已知限制與可選擴充](#十已知限制與可選擴充) | 評估要不要自己加東西 |

---

## 一、它解決什麼問題

要發一張「只在 15 分鐘內有效」的加密票據給前端或下游系統，而且要保證：

1. 內容只有持有金鑰的人看得懂（機密性）
2. 內容被改一個 bit 就會被發現（完整性）
3. 過期就不能用（時效性）
4. 旁觀者連「這張票何時到期」都看不到

GCM 一次解決 1 和 2，`Payload` 把 3 和 4 包進去，`KeyRef` 的 kid 另外補上「全面撤銷」的能力。

> GCM 屬於 **AEAD**（Authenticated Encryption with Associated Data）模式，加密與認證一次完成。
> 為什麼這很重要、以及為什麼不該用 CBC，見 [AEAD 是什麼，為什麼重要](#aead-是什麼為什麼重要)。

---

## 二、60 秒上手

```java
import io.github.cboheng.commontools.crypto.AesGcmHelper;
import io.github.cboheng.commontools.crypto.AesGcmHelper.KeyRef;
import io.github.cboheng.commontools.crypto.AesGcmHelper.Payload;
import java.time.Duration;
import java.time.Instant;

// ── 準備金鑰與它的 kid（整個應用程式共用一組，從 KMS / 環境變數取得）──
KeyRef keyRef = KeyRef.ofBase64(
        System.getenv("TOKEN_ENCRYPTION_KEY"),      // AES-256 金鑰的 Base64
        System.getenv("TOKEN_ENCRYPTION_KID"));     // 例如 "2026-10"

// ── 發行：一張 15 分鐘後失效的票 ──
String token = AesGcmHelper.encryptPayload(
        Payload.validFor("user-42", Duration.ofMinutes(15)), keyRef);

// ── 驗證：解密 + 明確檢查時效 ──
Payload payload = AesGcmHelper.decryptPayload(token, keyRef)
        .requireNotExpired(Instant.now());

String subject = payload.subject();                  // "user-42"
```

四件事要記住：

1. **`decryptPayload` 不檢查時效。** 它只保證「這張 token 是用這把金鑰＋這個 kid 發的、內容沒被改過」。要擋過期，必須自己接 `.requireNotExpired(...)`。
2. **`kid` 必須加解密兩端一致。** kid 被餵進 AAD、不隨 token 傳輸，所以兩端設定不同步時，所有 token 都會解不開。見 [kid 做什麼](#kid-做什麼)。
3. **`token` 是 URL-safe 的**（不含 `+` `/` `=`），可以直接丟進 query string、HTTP header、cookie。
4. **同一份資料加密兩次會得到不同的 token。** 這是正確行為，見 [為什麼輸出不固定](#iv-nonce為什麼每次都要換)。

### 要處理的三種結果

```java
try {
    Payload payload = AesGcmHelper.decryptPayload(token, keyRef)
            .requireNotExpired(Instant.now());
    // ✅ 正常：token 是真的、沒被改過、還在有效期內

} catch (AesGcmHelper.TokenExpiredException e) {
    // ⏰ token 是真的，但過期了。e.expired() 可取得到期時間。
    //    處置：請使用者重新取得。這是正常的業務流程，不是攻擊。

} catch (AesGcmHelper.TokenInvalidException e) {
    // 🚨 格式錯 / 被篡改 / 金鑰或 kid 不符。
    //    處置：視為攻擊訊號，記錄下來（連同來源 IP），不要回傳細節給對方。
    //    但先確認不是自己的 kid 設定沒同步——那會長得跟攻擊一模一樣。
}
```

兩個例外都繼承 `AesGcmHelper.CryptoException`，所以想一起處理就 catch 父類別。

---

---

## 三、API 一覽

```java
// ---- KeyRef：金鑰 + 金鑰識別碼（kid 會被餵進 AAD）----
record    KeyRef(SecretKey key, String kid)              // 建構時就驗證：必須是 AES-256，否則 IllegalArgumentException
KeyRef    KeyRef.of(byte[] raw, String kid)              // raw 會被複製，只收 32 bytes
KeyRef    KeyRef.ofBase64(String base64Key, String kid)   // 標準與 URL-safe 字元表皆可
KeyRef    KeyRef.generate(String kid)                    // 產生新的 AES-256 金鑰
String    keyRef.keyToBase64()                           // URL-safe Base64，可直接交給 ofBase64

// ---- 加解密（主要入口）----
String  encryptPayload(Payload payload, KeyRef keyRef)
Payload decryptPayload(String token, KeyRef keyRef)    // 只解密與解析，不檢查時效

// ---- Payload：時效判斷一律由應用層明確呼叫 ----
record  Payload(String subject, Instant expired)
Payload Payload.validFor(String subject, Duration ttl) // 現在 + ttl
boolean payload.isExpired(Instant now)                 // 回布林，後續怎麼處理由你決定
Payload payload.requireNotExpired(Instant now)         // 過期 → TokenExpiredException；否則回傳自己

// ---- 底層 AEAD（不含時效性語意）----
String encrypt(byte[] plaintext, KeyRef keyRef)
byte[] decrypt(String token, KeyRef keyRef)
```

### 實際跑起來長什麼樣

以下是真實執行輸出（非示意），`kid = "2026-10"`：

```text
KeyRef : KeyRef[kid=2026-10, key=<隱藏>]
Token  : AQZTPI41kFEsYEBPcJ1OLLBqB7AtofP7ZrRwEztDHsWUm26mBWTwzyHSz3A
字元數 : 59 / bytes: 44

VERSION   [0]       1 byte  : 01
IV        [1..13)  12 bytes : 06533C8E3590512C60404F70
CIPHERTEXT[13..28) 15 bytes : 9D4E2CB06A07B02DA1F3FB66B47013
TAG       [28..44) 16 bytes : 3B431EC5949B6EA60564F0CF21D2CF70

AAD（不在 token 裡，加解密兩端各自算出）:
  VERSION || "2026-10" = 01323032362D3130

--- 正常解開 ---
subject=user-42, expired=2026-10-06T09:00:00Z

--- 同一把金鑰，但 kid 換成 2026-11（模擬輪替 kid）---
TokenInvalidException: token 驗證失敗（金鑰或 kid 不符，或內容已被篡改）
  cause: javax.crypto.AEADBadTagException: Tag mismatch

--- token 長度完全不受 kid 長度影響 ---
kid  2 bytes -> token 59 chars
kid  7 bytes -> token 59 chars
kid 44 bytes -> token 59 chars
```

幾個可以從輸出直接讀出來的點：

- **同一把金鑰，只要 kid 不同就解不開**（`Tag mismatch`）。這就是 `kid` 餵進 AAD 的實際效果，也等於「改 kid = 全面撤銷所有已發出的 token」。
- **token 長度完全不受 kid 長度影響**（2 / 7 / 44 bytes 的 kid 都是 59 字元）。這是 kid 只存在於 AAD、不寫進 token 的直接證據。
- `AAD = 01323032362D3130`，就是 `0x01`（版號）接上 `"2026-10"` 的 UTF-8。這串資料兩端各自算出來，不隨 token 傳輸。
- `KeyRef.toString()` 只印 kid，金鑰被遮成 `<隱藏>`，避免它隨手被塞進 log。
- 固定成本是 `version(1) + IV(12) + expired(8) + tag(16) = 37 bytes`，Base64 後約 50 字元，**token 不會比這更短**。

---

## 四、實戰場景

兩個場景共用同一組 `KeyRef`，從環境變數載入：

```java
KeyRef keyRef = KeyRef.ofBase64(
        System.getenv("TOKEN_ENCRYPTION_KEY"),      // AES-256 金鑰的 Base64
        System.getenv("TOKEN_ENCRYPTION_KID"));     // 例如 "2026-10"
```

產生一把新金鑰：`KeyRef.generate("2026-10").keyToBase64()`。

> 金鑰不要 commit 進 git；key 與 kid 要當成一組一起更新，只換其中一個，所有 token 都會解不開。

### 場景 1：一般加解密

```java
byte[] plaintext = "任意資料".getBytes(StandardCharsets.UTF_8);

String token = AesGcmHelper.encrypt(plaintext, keyRef);
byte[] restored = AesGcmHelper.decrypt(token, keyRef);
```

`encrypt` / `decrypt` 是底層 AEAD，不帶時效語意，適合加密設定檔欄位、資料庫欄位等。

> 要指定編碼。無參數的 `getBytes()` 依賴平台預設編碼，換台機器可能解出亂碼。

### 場景 2：時效性加解密

以 10 分鐘有效的下載連結為例：

```java
public String createDownloadUrl(String fileId) {
    String token = AesGcmHelper.encryptPayload(
            Payload.validFor(fileId, Duration.ofMinutes(10)), keyRef);
    return "https://example.com/download?t=" + token;   // token 本身即 URL-safe
}

public InputStream handleDownload(String token) {
    Payload payload;
    try {
        payload = AesGcmHelper.decryptPayload(token, keyRef)
                .requireNotExpired(Instant.now());        // 不接這行就不會檢查時效
    } catch (AesGcmHelper.TokenExpiredException e) {
        throw new DownloadLinkExpiredException("連結已失效，請重新產生");
    } catch (AesGcmHelper.TokenInvalidException e) {
        log.warn("收到無效的下載 token", e);
        throw new ForbiddenException();                   // 對外不解釋原因
    }
    return storage.open(payload.subject());               // subject 就是 fileId
}
```

- 要容許時鐘偏移，把「現在」往回調：`requireNotExpired(Instant.now().minusSeconds(30))`。
- 連結在有效期內可以重複使用；改 kid 能一次撤銷全部，但無法只撤銷一張，見 [重放與撤銷](#重放與撤銷)。

---

## 五、加密方式細節

### 用到了什麼

| 元件 | 選擇 | 作用 |
|---|---|---|
| 對稱加密演算法 | **AES**（只收 256-bit 金鑰） | 把明文變成看不懂的密文 |
| 運作模式 | **GCM**（Galois/Counter Mode） | 讓 AES 能處理任意長度資料，**並同時產生認證標籤** |
| Padding | **NoPadding** | GCM 是 counter 模式，明文不必對齊 16-byte block，所以不需要填充 |
| IV / nonce | 12 bytes，每次由 `SecureRandom` 重新產生 | 讓同樣的明文每次產生不同密文 |
| 認證標籤 (tag) | 16 bytes (128-bit) | 密文被改動就驗不過 |
| AAD | `版號(1 byte) + kid` | 不加密但納入認證的附加資料。**kid 放在這裡**，所以它不外洩也不可篡改 |
| 編碼 | Base64URL（無 padding） | 讓 token 可以安全地放進 URL |

### AEAD 是什麼，為什麼重要

**AEAD = Authenticated Encryption with Associated Data**，一次同時提供兩件事：

- **機密性**（confidentiality）：沒有金鑰看不懂內容。
- **完整性 / 真實性**（integrity / authenticity）：內容被改過會被發現，而且只有持有金鑰的人能產生有效的 token。

GCM 屬於 AEAD。密文被改一個 bit，`doFinal()` 就會拋 `AEADBadTagException`，**不會回傳可疑的明文**。

對照之下，CBC 這類傳統模式**只負責加密、不負責認證**。你必須自己外掛 HMAC，而且：

- 順序要對（必須 Encrypt-then-MAC）
- MAC 要蓋住 IV，不能只蓋密文
- 比較 MAC 要用常數時間比較

這三件事任一個做錯，就是 padding oracle 這類經典漏洞的來源。**能用 GCM 就不要用 CBC；絕對不要用 ECB。**

### GCM 內部大致怎麼運作

概念上兩條線並行（理解用，非精確規格）：

```
加密線：AES 以 counter 模式產生 keystream，與明文 XOR → 密文
        counter 的起點由 IV 決定

認證線：把 AAD 與密文餵進 GHASH（在 GF(2^128) 上的乘法累加）
        結果再與 AES 加密過的 counter-0 區塊結合 → 16-byte tag
```

兩個關鍵推論，會直接影響你怎麼用它：

1. **密文長度 = 明文長度**（因為是 XOR，沒有 padding）。所以 token 長度會洩漏資料長度，見 [長度洩漏](#長度洩漏token-會洩漏-subject-有多長)。
2. **IV 決定 counter 起點**。同一把金鑰配同一個 IV，keystream 就完全相同——這是 [IV 重用致命](#iv-nonce為什麼每次都要換) 的根本原因。

### Token 格式

```
Base64URL( VERSION(1) | IV(12) | CIPHERTEXT(n) | TAG(16) )
                                └── doFinal() 的輸出 ──┘

密文內部（必須解密才看得到）：
    EXPIRED(8, big-endian epoch milli) | SUBJECT(UTF-8, 剩餘全部)
```

AAD（**不隨 token 傳輸**，加解密兩端各自算出）：

```
AAD = VERSION(1) | kid 的 UTF-8 bytes
```

### 逐 byte 解剖一個真實 token

以下是實際跑出來的結果（`subject = "user-42"`、`expired = 2026-10-06T09:00:00Z`、`kid = "2026-10"`）：

```text
KeyRef : KeyRef[kid=2026-10, key=<隱藏>]
Token  : AQZTPI41kFEsYEBPcJ1OLLBqB7AtofP7ZrRwEztDHsWUm26mBWTwzyHSz3A
字元數 : 59 / bytes: 44

VERSION   [0]       1 byte  : 01
IV        [1..13)  12 bytes : 06533C8E3590512C60404F70
CIPHERTEXT[13..28) 15 bytes : 9D4E2CB06A07B02DA1F3FB66B47013
TAG       [28..44) 16 bytes : 3B431EC5949B6EA60564F0CF21D2CF70

AAD（不在 token 裡，加解密兩端各自算出）:
  VERSION || "2026-10" = 01323032362D3130

--- 密文解開後的明文（解密才看得到）---
明文全長       : 15 bytes
EXPIRED [0..8) : 000001A11070F280  = 1791277200000 = 2026-10-06T09:00:00Z
SUBJECT [8..]  : 757365722D3432  = "user-42"
```

數字自己就對得起來：

- 明文 = `expired`(8) + `"user-42"`(7 bytes UTF-8) = **15 bytes**
- 密文長度 = 明文長度 = **15 bytes**（GCM 無 padding）
- 總長 = 1 + 12 + 15 + 16 = **44 bytes**
- Base64 無 padding：`ceil(44 / 3) * 4 - 1` = **59 字元**
- AAD = `01` + `323032362D3130`，後者正是 `"2026-10"` 的 UTF-8。**它不在那 44 bytes 裡面。**

**固定成本是 37 bytes**（version 1 + IV 12 + expired 8 + tag 16），Base64 後約 50 字元。**token 不可能比這更短**，所以傳很短的 subject 時額外負擔相對明顯。

而 kid 完全不影響 token 長度——實測 2 bytes、7 bytes、44 bytes 的 kid 都產生 59 字元的 token：

```text
kid  2 bytes -> token 59 chars
kid  7 bytes -> token 59 chars
kid 44 bytes -> token 59 chars
```

> IV 每次都不同，所以你自己跑出來的 token 不會跟上面一樣——只有 `VERSION`、各段長度、AAD、以及明文區的 `EXPIRED` / `SUBJECT` 會對得上。

### AAD 裡有什麼：版號與 kid

AAD（Additional Authenticated Data）是「不加密但納入認證」的資料：它不會被加密、也不隨 token 傳輸，但**改動它就會導致驗證失敗**。

```
AAD = VERSION(1 byte) | kid 的 UTF-8 bytes
```

AAD 的唯一要求是「加解密兩端算出完全相同的 byte 序列」。版號固定佔第一個 byte，所以 (版號, kid) 的不同組合不會產生相同的 AAD——這也是為什麼 `KeyRef` **禁止空 kid**：空 kid 會讓 AAD 退化成只剩版號。

#### kid 做什麼

kid（key id）是你自己定義的金鑰識別碼。把它放進 AAD 換到兩個能力：

**1. 把金鑰身分綁進密文。** 金鑰對、kid 不對，驗證一樣失敗：

```java
String token = AesGcmHelper.encryptPayload(payload, new KeyRef(key, "2026-10"));

// 同一把金鑰，kid 換掉 → 解不開
AesGcmHelper.decryptPayload(token, new KeyRef(key, "2026-11"));
// → TokenInvalidException，cause 是 AEADBadTagException: Tag mismatch
```

**2. 改 kid 等於全面撤銷。** 不必換金鑰，只要改掉 kid，**所有已發出的 token 立刻全部失效**。這補上了絕對到期時間這種無狀態設計本來缺少的撤銷能力。

#### kid 不會出現在 token 裡

這是明確的取捨：

| | 本工具（kid 只在 AAD） | 若把 kid 放進明文 header |
|---|---|---|
| kid 是否外洩 | ❌ 不外洩 | ✅ 公開可見 |
| token 長度 | 不受 kid 長度影響 | 隨 kid 變長 |
| 新舊 kid 並存 | ❌ 做不到 | ✅ 可以 |
| 平滑輪替 | ❌ 換 kid 的瞬間所有在途 token 全死 | ✅ 有過渡期 |

**所以 kid 輪替在本工具裡是「撤銷手段」，不是「例行輪替手段」。** 除非你能接受使用者手上的票全部作廢。

若需要平滑過渡期，做法是把 kid 放進 token 的明文 header——這是 RFC 7515 中 JWS `kid` 的慣例（「*a hint indicating which key was used to secure the JWS*」，明文的「該用哪把金鑰」提示），解密方先讀 kid、再查對應金鑰。那需要把 token 格式升到 v2。

#### 為什麼版號也要餵進 AAD

目前只有 v1，所以實質效益有限。價值在未來：如果日後推出 v2 格式，攻擊者不能把 v2 的密文搬到 v1 的 header 底下重放，因為 AAD 不符會導致驗證失敗。這在密碼學上叫 **domain separation**（領域分離）。

這個做法有業界先例：**Branca** 規格明文要求 "Use header as the additional data for the AEAD"，把 `version | timestamp | nonce` 整段 header 當 AAD。而把 key id / key version 放進 AAD 則是 envelope encryption 的常見模式，目的正是「把金鑰綁定到密文，確保 mismatch 能被偵測」。

> 測試 `aadIsActuallyAuthenticated` 專門守這件事：它繞過 helper、用相同金鑰但**不餵 AAD** 組出一個格式完全正確的 token，證明 helper 解不開它。單純測「篡改會失敗」抓不到 `updateAAD` 寫了卻沒生效的情況，因為版號檢查會先把它擋掉。

---

## 六、安全性細節

### 威脅模型：防什麼、不防什麼

| 威脅 | 防護 | 說明 |
|---|---|---|
| 旁觀者讀取 token 內容 | ✅ | AES-256 加密，`subject` 與 `expired` 都在密文裡 |
| 篡改 token 內容 | ✅ | 128-bit GCM tag。測試逐一翻轉每個 byte，全部被攔下 |
| 無金鑰偽造 token | ✅ | 產生有效 tag 需要金鑰 |
| 從 token 推測到期時間 | ✅ | `expired` 在密文內 |
| 看出兩次送的是同一份資料 | ✅ | 每次重新隨機產生 IV |
| 用錯金鑰版本（kid）被偵測 | ✅ | kid 在 AAD 裡，金鑰對但 kid 不對一樣解不開 |
| 偵知 token 用哪個 kid 加密 | ✅ | kid 不在 token 裡，token 長度也不洩漏 kid 長度 |
| **全面撤銷已發出的 token** | ✅ | 改掉 kid 即可，不必換金鑰。但這是「全死」，沒有過渡期 |
| **撤銷單一張 token** | ❌ | 做不到。改 kid 是全部作廢，沒有「只撤銷這一張」的機制 |
| **有效期內的重放** | ❌ | 同一張 token 可被無限次使用，見下 |
| **平滑金鑰輪替** | ❌ | 新舊 kid 無法並存，換 kid 的瞬間在途 token 全死 |
| **`subject` 長度洩漏** | ❌ | token 長度與 subject 長度線性相關，見下 |
| 金鑰洩漏 | ❌ | 不在本工具範圍，交給 KMS / Vault |
| 阻斷服務（DoS） | ❌ | 大量無效 token 仍會消耗 CPU |
| 時間側通道 | ❓ | JCE 的 tag 比較預期為常數時間，但**本專案未驗證**此事 |

### 重放與撤銷

```java
String token = issue("user-42", Duration.ofMinutes(15));
// 這張 token 在 15 分鐘內，可以被使用 1 次、也可以被使用 100 萬次。
// 攔截到它的人，在 15 分鐘內就是 user-42。
```

**時效性不等於單次使用。** 這是絕對到期時間這種無狀態設計的本質限制，不是 bug。

至於**撤銷**，kid 給了你一半的答案：

```bash
# 把環境變數的 kid 從 2026-10 改成 2026-11（金鑰完全不必動）
# → 所有已發出的 token 立刻全部失效
```

但請認清這是**全有全無**的開關：

| 需求 | kid 輪替 |
|---|---|
| 全面撤銷（例如懷疑金鑰外洩） | ✅ 改一個環境變數就行 |
| 只撤銷某一張 token | ❌ 做不到 |
| 只撤銷某一位使用者 | ❌ 做不到 |
| 有過渡期的輪替 | ❌ 在途 token 會全死 |

其餘的緩解方向（都需要你自己加，本工具刻意不做，因為會破壞「零依賴」）：

| 需求 | 做法 | 代價 |
|---|---|---|
| 單次使用 | token 內放一個隨機 id（需升格式到 v2），用後存進 Redis 並設 TTL = token 剩餘壽命 | 需要外部儲存、每次驗證多一次 I/O |
| 單張 / 單人撤銷 | 維護黑名單（存 token id 或 subject） | 同上 |
| 平滑輪替 | kid 改放 token 明文 header（升格式到 v2），解密方依 kid 查金鑰 | kid 公開、token 變長、需維護 kid → key 對應表 |
| 縮小爆炸半徑 | **把 TTL 設短**（分鐘級而非小時級） | 使用者需要更頻繁地重新取得 |
| 綁定使用者 | token 內放 IP 或 device id 並在驗證時比對 | 行動網路換 IP 會誤殺 |

**最便宜且有效的一招是把 TTL 設短。** 在加任何基礎設施之前先考慮這個。

### 長度洩漏：token 會洩漏 subject 有多長

GCM 不做 padding，所以密文長度 = 明文長度，token 長度就跟著 `subject` 的 UTF-8 長度線性變動。實測：

```text
subject  1 bytes -> token 51 chars (38 bytes)
subject  7 bytes -> token 59 chars (44 bytes)
subject 27 bytes -> token 86 chars (64 bytes)
```

旁觀者看一眼 token 長度，就能推算 `subject` 有幾個 byte。

什麼時候這會是問題：`subject` 的長度本身帶有資訊。例如 subject 放的是使用者姓名、或是「長度能區分帳號類型」（內部帳號 5 碼、外部帳號 20 碼）。

緩解：

```java
// 做法 1：固定長度的識別碼（UUID 一律 36 字元，長度不帶資訊）
Payload.validFor(userUuid.toString(), ttl);

// 做法 2：自行補到固定長度
String padded = String.format("%-32s", subject);     // 補空白到 32 字元
// 解開後記得 strip()
```

### IV / nonce：為什麼每次都要換

**同一把金鑰配同一個 IV 加密兩次，GCM 的安全性會直接崩潰。** 不是「稍微變弱」，是崩潰：

- 兩段密文 XOR 起來，等於兩段明文 XOR——keystream 被消掉了，明文差值直接外洩。
- 更糟的是可能導致 **authentication key 洩漏**，讓攻擊者能偽造任意訊息的 tag。

所以本工具：

- 每次加密都用 `SecureRandom` 產生新的 12-byte IV
- **刻意不開放讓呼叫端指定 IV** —— 少一個能把自己害死的旋鈕

> 代價：無法做確定性加密（deterministic encryption）。如果你需要「同樣的輸入產生同樣的密文」來做資料庫索引或去重，這個工具不適合，那需要 AES-SIV 之類的 nonce-misuse resistant 方案。

### 同一把金鑰能加密幾次

依 **NIST SP 800-38D §8.3**，在隨機 IV 的做法下，同一把金鑰的加密次數應限制在 **2^32 次**以內，以把 nonce 碰撞機率壓在 2^-32 以下。

2^32 ≈ 43 億次。一般應用很難碰到，但如果你是每秒發幾萬張 token 的規模，請把金鑰輪替排進規劃。

**真的逼近這個量級時，該做的是輪替金鑰，不是加長 IV。** 12-byte IV 是 NIST 建議值，改長反而會讓 GCM 多做一次 GHASH 衍生。

### 金鑰管理（不在本工具範圍內）

`KeyRef.generate()` 只負責產生金鑰。放哪裡、怎麼輪替、誰能讀，是你的基礎設施要解決的。

**key 與 kid 要當成一組不可分割的設定來發布。** 只更新其中一個，所有 token 都會解不開，而且錯誤訊息跟被攻擊長得一模一樣。kid 本身**不是秘密**（它只是識別碼），但必須兩端一致。

- ✅ KMS（AWS KMS / GCP KMS / Azure Key Vault）、HashiCorp Vault
- ✅ 環境變數（容器環境的常見折衷）
- ❌ 寫死在程式碼裡
- ❌ commit 進 git（包含 `application.yml`、`.env`）
- ❌ 寫進 log

> 只收 AES-256，`KeyRef` 建構時就會驗證演算法與長度。設定錯誤會在啟動時直接失敗，不會等到加解密時才變成一個看起來像「token 被篡改」的 `TokenInvalidException`。無法匯出的金鑰（例如放在 HSM 裡、`getEncoded()` 回傳 null）量不到長度，也一律拒絕。

### 錯誤訊息刻意不區分

`TokenInvalidException` 的訊息一律是「金鑰或 kid 不符，或內容已被篡改」，**不告訴對方是哪一種**。這是為了少給攻擊者一個 oracle。

> 反面代價：排錯時你自己也分不出「被攻擊」與「我的 kid 沒同步」。**部署後突然大量出現這個例外時，先去比對兩邊的 kid 設定**，不要第一時間往攻擊方向查。

要 debug 請看 `getCause()`，那裡才有 `AEADBadTagException: Tag mismatch` 這種細節。**對外回應不要帶上 `getMessage()`，更不要帶 cause。**

### 明文清零的限制

`encryptPayload` / `decryptPayload` 內部的明文緩衝區，在 `finally` 裡會 `Arrays.fill(..., (byte) 0)`，縮短敏感資料待在 heap 上的時間。

**但這對 `String subject` 無效。** Java 的 `String` 不可變、無法清除，要等 GC。如果 `subject` 極度敏感（例如身分證號、信用卡號），應考慮：

- 改放不可逆的識別碼（UUID、雜湊）而非原始敏感值 ← **推薦**
- 或改用 `char[]` / `byte[]` 的 payload 設計（需改寫本工具）

### `Cipher` 不是 thread-safe

本工具每次加解密都 `Cipher.getInstance()` 新建一個，**絕不共用 static 實例**。

把 `Cipher` 存成 `static` 欄位共用，是多執行緒下最常見的加密災難——會解出別人的資料，或直接拋出莫名的例外。如果你要 copy 這段程式碼去改，請保留這個做法。

`SecureRandom` 則是 thread-safe，所以共用一份沒問題。

### 解密前不要信任任何 bytes

GCM 的認證發生在 `doFinal()`。在那之前拿到的任何資料都**還沒驗證過**。

本工具刻意不提供 streaming 解密介面（`CipherInputStream` 之類），就是為了避免呼叫端在驗證完成前就開始處理資料——那等於放棄了 GCM 的完整性保護。

---

---

## 七、時效性細節

### 設計摘要

| 項目 | 本工具的選擇 |
|---|---|
| 時戳語意 | **絕對到期時間**（`expired`），由發行方決定 |
| 時戳位置 | **密文內**，必須解密才看得到 |
| 精度 | **毫秒**（8 bytes epoch milli） |
| 到期邊界 | `now >= expired` 即算過期，不給寬限 |
| 誰判斷 | **應用層**。`decryptPayload` 不檢查 |
| 時鐘來源 | 呼叫端傳入的 `Instant now` |

### 為什麼 `decryptPayload` 不自動檢查

這是刻意的職責切分：helper 只負責「安全地把 `expired` 帶進密文、再帶出來」。**判斷的時機、用哪個時鐘、是否容許偏移，都是應用層的決定。**

換到的好處：

- 時鐘可注入 → 測試能凍結時間，精確驗證到期邊界
- 偏移容許窗不需要新 API → `requireNotExpired(Instant.now().minusSeconds(30))`
- 過期也能讀出內容做稽核：不接 `requireNotExpired`，改用 `payload.isExpired(now)` 判斷後記錄

**代價很明確：呼叫端漏寫 `requireNotExpired` 就會靜默失效**——沒有錯誤、沒有 log、測試照樣過。這是把預設從 fail-safe 改成 fail-open。

所以**請把兩步串成一行**，讓「少做了檢查」在 code review 時一眼看得出來：

```java
AesGcmHelper.decryptPayload(token, keyRef).requireNotExpired(Instant.now())
```

> 業界兩種做法都有：JJWT 預設會檢查 `exp` 並拋 `ExpiredJwtException`（fail-safe）；Fernet 與 Branca 的 TTL 是解密時的可選參數，不傳就不檢查（fail-open）。本工具走後者。

### 為什麼時戳放密文內

`expired` 跟 `subject` 一起被加密，**不是**放在明文 header。

- **好處**：旁觀者連「這張票何時到期」都看不到。
- **代價**：必須先完成解密才知道 token 早就過期。每個過期請求都要付一次完整的 AES 成本。

這在正常流量下無感，但被灌入大量過期 token 時會是放大器。如果你的場景需要「不解密就先擋掉過期請求」，業界做法是把時戳改放明文 header 並納入認證範圍：

| 方案 | 時戳位置 | 可否不解密就判斷 |
|---|---|---|
| **本工具** | 密文內 | ❌ 必須解密 |
| **Fernet** | 明文，納入 HMAC 範圍 | ✅ |
| **Branca** | 明文 header，整段當 AAD | ✅ |

> Fernet 與 Branca 的時戳存的都是**建立時間**（搭配驗證方傳入的 TTL），而非到期時間。

### 毫秒精度與奈秒陷阱

token 內只存 8 bytes 的 `epochMilli`，所以 `Instant` 的**奈秒會被丟掉**。

如果不處理，`new Payload(s, t)` 與解密後拿回的 Payload 會因為奈秒遺失而不相等——這是會讓人查一整天的那種 bug。

本工具在 `Payload` 的 canonical constructor 就 `truncatedTo(ChronoUnit.MILLIS)`，**把問題消滅在型別邊界**：

```java
Payload p = new Payload("user-42", Instant.parse("2030-01-01T00:00:00.123456789Z"));
p.expired();     // → 2030-01-01T00:00:00.123Z   奈秒在這裡就被截掉了
```

所以 round-trip **必然**相等。副作用是你傳進去的 `expired` 可能跟 `payload.expired()` 不同（差在奈秒），這是刻意的。

### 到期邊界

```java
payload.isExpired(payload.expired());                  // true  ← 到期那一刻即過期
payload.isExpired(payload.expired().plusMillis(1));    // true
payload.isExpired(payload.expired().minusMillis(1));   // false ← 到期前 1 毫秒仍有效
```

採 `now >= expired` 算過期，**不給寬限**。需要寬限請自己調整傳入的 `now`。

### `Instant.MAX` 會在建構時被擋下

```java
new Payload("user-42", Instant.MAX);
// → IllegalArgumentException: expired 超出可表示範圍（必須能表示為 epoch milli）
```

`Instant.MAX.toEpochMilli()` 會 overflow。在建構時就擋掉，而不是等到加密那一刻才拋出難以解釋的 `ArithmeticException`。

---

---

## 八、常見錯誤用法

Code review 對照表。

### ❌ 忘記檢查時效

```java
// 錯：時效性完全失效，而且毫無徵兆
Payload payload = AesGcmHelper.decryptPayload(token, keyRef);
return payload.subject();
```

```java
// 對
return AesGcmHelper.decryptPayload(token, keyRef)
        .requireNotExpired(Instant.now())
        .subject();
```

### ❌ 把稽核路徑當驗證路徑

```java
// 錯：記了 log 但還是放行
Payload payload = AesGcmHelper.decryptPayload(token, keyRef);
if (payload.isExpired(Instant.now())) {
    log.warn("token 過期");       // ← 只記 log，沒有 return/throw
}
return payload.subject();
```

### ❌ 把加密層細節回給呼叫方

```java
// 錯：洩漏「是金鑰錯還是內容被改」，等於送對方一個 oracle
catch (TokenInvalidException e) {
    return ResponseEntity.status(401).body(e.getMessage());
}
```

```java
// 對：對外一律「不行」，細節只進 log
catch (TokenInvalidException e) {
    log.warn("無效 token，來源 {}", clientIp, e);
    return ResponseEntity.status(401).body(Map.of("error", "token_invalid"));
}
```

### ❌ 每次請求產生新金鑰

```java
// 錯：下一個請求用新金鑰，當然解不開上一張 token
public String verify(String token) {
    KeyRef keyRef = KeyRef.generate("v1");   // ← 每次都是新金鑰
    return AesGcmHelper.decryptPayload(token, keyRef).subject();
}
```

`KeyRef` 應該是**應用程式層級的單一實例**，從 KMS / 環境變數載入一次。

### ❌ 把 kid 寫死在程式碼裡

```java
// 錯：kid 寫死，就等於放棄了「改 kid 全面撤銷」這個唯一的撤銷手段
KeyRef keyRef = new KeyRef(key, "v1");
```

```java
// 對：kid 跟 key 一樣從設定來，才有辦法在需要時換掉
KeyRef keyRef = KeyRef.ofBase64(
        System.getenv("TOKEN_ENCRYPTION_KEY"),
        System.getenv("TOKEN_ENCRYPTION_KID"));
```

### ❌ 只更新 key 或只更新 kid

部署時只改了其中一個，所有 token 立刻解不開，而錯誤訊息會說「金鑰或 kid 不符」——跟被攻擊一模一樣，很容易往錯的方向查半天。

**把 key 與 kid 當成一組不可分割的設定來發布。**

### ❌ 把 kid 輪替當成例行的金鑰輪替

```java
// 錯誤的心智模型：「每月換 kid，像換金鑰一樣安全又平滑」
// 實際：換 kid 的那一瞬間，所有使用者手上的票全部失效
```

kid 輪替在本工具裡是**撤銷手段**（懷疑外洩時用），不是平滑輪替手段。因為 kid 不在 token 裡，解密方無從判斷某張 token 屬於哪個 kid，新舊無法並存。

需要有過渡期的輪替，得把 kid 放進 token 明文 header（升格式到 v2）。

### ❌ 以為 kid 是秘密

kid 只是識別碼，不是金鑰材料。它**不需要**像金鑰那樣保護——`KeyRef.toString()` 就會把 kid 印出來（只遮金鑰）。
反過來也別以為「kid 保密」能提供任何安全性：安全性完全來自金鑰，kid 的作用是綁定與撤銷。

### ❌ 用無參數的 `getBytes()`

```java
AesGcmHelper.encrypt(text.getBytes(), keyRef);                        // 錯：依賴平台預設編碼
AesGcmHelper.encrypt(text.getBytes(StandardCharsets.UTF_8), keyRef);  // 對
```

### ❌ 把 token 當 ID 存進資料庫做唯一索引

同一份 payload 每次加密都產生不同 token（因為 IV 隨機），所以 token **不能**當識別碼或去重的鍵。要識別請用 `subject`。

### ❌ 把金鑰寫進設定檔並 commit

```yaml
# 錯
app:
  token-key: wNf7otU-ztP7_TsuRXbeVeQ-mAOJy0LVtIp9dsHRA1Y
```

```yaml
# 對
app:
  token-key: ${TOKEN_ENCRYPTION_KEY}
```

### ❌ 共用 static 的 `Cipher`

如果你 copy 這份程式碼去改，不要為了「效能」把 `Cipher` 提成 static 欄位。`Cipher` 不是 thread-safe。

---

---

## 九、設計決策與取捨

| 決策 | 選擇 | 取捨 / 理由 |
|---|---|---|
| 加密模式 | AES/GCM/NoPadding | AEAD，加密與認證一次完成。GCM 是 counter 模式，明文不必對齊 block，所以不需要 padding |
| IV 長度 | 12 bytes (96-bit) | NIST SP 800-38D 建議值，也是唯一不需額外做 GHASH 衍生的長度 |
| Tag 長度 | 16 bytes (128-bit) | GCM 允許的最長，通用場景唯一該用的長度 |
| IV 來源 | 一律 `SecureRandom`，不開放指定 | 少一個能把自己害死的旋鈕。代價：無法做確定性加密（deterministic encryption），需要的話得另設計 |
| **時戳位置** | **密文內（完全隱藏）** | 旁觀者看不到到期時間。**代價：必須先完成解密才知道 token 早就過期**，每個過期請求都要付一次 AES 成本 |
| 時效語意 | 絕對到期時間 `expired`，由發行方決定 | 語意直觀。代價：token 發出後無法縮短有效期；驗證方無權再收緊 |
| **誰判斷過期** | **應用層**。`decryptPayload` 只解密與解析，絕不自動檢查 | 單一職責；時鐘由呼叫端注入，所以可凍結測試、可自訂偏移容許窗；過期也能讀出內容做稽核。**代價：呼叫端漏寫檢查就會靜默失效**——沒有錯誤、沒有 log、測試照樣過 |
| 序列化 | 固定長 8 bytes + 剩餘全是 subject | 無分隔符歧義、零依賴（不需 JSON 函式庫）。代價：格式自訂，跨語言需自行實作 |
| 例外型別 | unchecked（`RuntimeException` 子類） | 呼叫端不必被迫 catch 七種 `GeneralSecurityException`——這正是 helper 存在的價值 |
| 檔案組織 | `Payload` 與例外都是 nested type | 符合「COPY 一個檔案即可使用」。代價：型別名變成 `AesGcmHelper.Payload` 稍長，可用 `import ...AesGcmHelper.Payload;` 解決 |
| 版號納入 AAD | 是 | 為格式演進預留 domain separation。**目前只有 v1，實質效益有限**；價值在未來新增 v2 時，攻擊者無法把 v2 密文搬到 v1 header 下重放 |
| **kid 納入 AAD** | 是，`AAD = VERSION \| kid` | 把金鑰身分綁進密文：金鑰對但 kid 不對一樣解不開。**附帶換到「全面撤銷」能力**——不換金鑰、只改 kid，所有已發出的 token 立刻失效 |
| **kid 不寫進 token** | 是（只存在於 AAD） | kid 不外洩、token 不變長。**代價：無法平滑輪替**，換 kid 的那一刻使用者手上的票全死。要平滑過渡得把 kid 放進明文 header（RFC 7515 中 JWS `kid` 的慣例），需升格式到 v2 |
| key 與 kid 的載體 | 綁成 `KeyRef` record | 結構上排除「用 A 的 key 配 B 的 kid」。那種配錯會讓所有 token 解不開，而訊息只說「金鑰或 kid 不符」，極難追查 |
| 空 kid | 禁止 | 空 kid 會讓 AAD 退化成只剩版號，與「沒有 kid 概念」的格式撞在一起 |

---

## 十、已知限制與可選擴充

> 以下都是**我的假設，沒有放進程式碼**。要不要加、怎麼加，由你決定。

| 可能的擴充 | 它會解決什麼 | 代價 |
|---|---|---|
| ~~可注入 `Clock`~~ | ~~無法凍結測試時間~~ | **已不需要**：時效判斷移到應用層後，`now` 本來就由呼叫端傳入 |
| ~~clock skew 容許窗~~ | ~~分散式環境時鐘有秒級差異~~ | **已不需要**：`requireNotExpired(Instant.now().minusSeconds(30))` 即為 30 秒寬限 |
| 時戳改放 AAD | 不解密就能擋掉過期請求（省 CPU、抗灌入） | 到期時間變成公開資訊 |
| kid 寫進 token 明文 header | **平滑輪替**：新舊 kid 並存期間兩種 token 都能解，不必讓在途 token 全死 | 格式需升到 v2、kid 公開、API 要多一個「kid → key」的查詢函數 |
| 增加 issuer / audience 等欄位 | 防止 token 被跨服務重放 | 格式需升到 v2，payload 變大 |
| 單次使用（nonce 台帳） | 防止 token 在有效期內被重複使用 | 需要外部儲存（Redis 等），helper 就不再是零依賴 |

---

## 延伸閱讀

- [NIST SP 800-38D — GCM 與 GMAC 的建議](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf)：IV 長度建議、§8.3 的 2^32 次限制
- [`GCMParameterSpec` javadoc (Java 25)](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/spec/GCMParameterSpec.html)：tag 長度允許值
- [Fernet Spec](https://github.com/fernet/spec/blob/master/Spec.md)：明文但被認證的 timestamp、驗證方給 TTL 的設計
- [Branca Spec](https://github.com/tuupola/branca-spec)：把整段 header 當 AAD
- [RFC 7515 — JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515.html)：`kid` 作為明文的「該用哪把金鑰」提示，§4.1.4 與 §6
- [../README.md](../README.md)：專案總覽與工具索引
