## 1. Record Pattern + Switch Pattern：可讀性大優化

| 特性 | 正式版本 | 作用 |
|---|---|---|
| [Pattern Matching for switch（JEP 441）](https://openjdk.org/jeps/441) | 21 | `switch` 可以依「型別」分派，不再只限 int / enum / String |
| [Record Patterns（JEP 440）](https://openjdk.org/jeps/440) | 21 | 比對型別的同時，直接把 record 的欄位拆出來 |
| [Sealed Classes（JEP 409）](https://openjdk.org/jeps/409) | 17 | `sealed ... permits A, B, C` 列出允許的子型別：編譯器知道總共有哪幾種，`switch` 少寫一種就**編譯失敗**，不需要 `default` |

### 範例：驗證 token 的結果（示意）

```java
sealed interface VerifyResult permits Valid, Expired, Invalid {}
record Valid(String subject, Instant expired) implements VerifyResult {}
record Expired(Instant expired)               implements VerifyResult {}
record Invalid(String reason)                 implements VerifyResult {}
```

<details open>
<summary>Java 8：instanceof 鏈 + 手動轉型</summary>

```java
String describe(VerifyResult r) {
    if (r instanceof Valid) {
        Valid v = (Valid) r;
        return "歡迎 " + v.getSubject();
    } else if (r instanceof Expired) {
        Expired e = (Expired) r;
        return "已於 " + e.getExpired() + " 過期";
    } else if (r instanceof Invalid) {
        return "拒絕";
    }
    throw new IllegalStateException("未知型別");   // 新增子型別時，編譯器不會提醒
}
```

</details>

<details open>
<summary>Java 21：switch pattern + record pattern</summary>

```java
String describe(VerifyResult r) {
    return switch (r) {
        case Valid(String subject, Instant exp) -> "歡迎 " + subject;
        case Expired(Instant exp)              -> "已於 " + exp + " 過期";
        case Invalid i                         -> "拒絕";
    };   // 少一個 case → 編譯錯誤；不需要 default
}
```

</details>

### 補充

**`permits` 是 contextual keyword**：只在類別宣告的特定位置才有特殊意義，不是保留字，舊程式照樣能編譯。

```java
int permits = 3;   // 合法，permits 在這裡只是普通變數名
```

**`permits` 可以省略**：子型別和父型別寫在同一個 `.java` 檔時，編譯器會自動推斷。

```java
// VerifyResult.java —— 子型別都在同一個檔案，permits 可省
sealed interface VerifyResult {}
record Valid(String subject, Instant expired) implements VerifyResult {}
record Expired(Instant expired)               implements VerifyResult {}
record Invalid(String reason)                 implements VerifyResult {}
```

**`when` 守衛**：在 case 上加條件。有守衛的 case 不算數進窮舉檢查，所以還是要留一個沒守衛的同型別 case，且要寫在後面。

```java
return switch (r) {
    case Valid(String subject, Instant exp) when exp.isBefore(Instant.now().plusSeconds(60))
                                            -> "歡迎 " + subject + "（即將過期）";
    case Valid(String subject, Instant exp) -> "歡迎 " + subject;
    case Expired(Instant exp)               -> "已於 " + exp + " 過期";
    case Invalid i                          -> "拒絕";
};
```

**`case null`**：以前 `switch` 遇到 null 一律丟 NPE，現在可以明確處理。

```java
return switch (r) {
    case null                               -> "沒有結果";
    case Valid(String subject, Instant exp) -> "歡迎 " + subject;
    case Expired(Instant exp)               -> "已於 " + exp + " 過期";
    case Invalid i                          -> "拒絕";
};
```

**巢狀拆解**：record 裡面還有 record，可以一層一層拆。

```java
record User(String id, String role) {}
record Valid(User user, Instant expired) implements VerifyResult {}   // 改成帶 User

case Valid(User(String id, String role), Instant exp) -> id + " 以 " + role + " 身分登入";
```

**不用的欄位寫 `_`**：Java 22 才正式的 [Unnamed Variables & Patterns（JEP 456）](https://openjdk.org/jeps/456)，Java 21 還不能用。

```java
case Valid(String subject, _) -> "歡迎 " + subject;   // 不需要 expired
case Expired _                -> "已過期";             // 整個都不需要
```
