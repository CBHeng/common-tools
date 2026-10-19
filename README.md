# common-tools

我的 Java Rust 的工具包，紀錄這些通用案例。

## 工具

- **[`AesGcmHelper`](java/src/main/java/io/github/cboheng/commontools/crypto/AesGcmHelper.java)**：AES-256-GCM 加解密，詳見 [docs/AesGcmHelper.md](docs/AesGcmHelper.md)
    - 加解密：認證加密，密文被改一個 bit 就解不開；輸出是 URL-safe token
    - 時效性：到期時間一起藏在密文裡，是否過期由應用層判斷

## 冷知識：敏感 bytes 用完就清零

```java
try {
    return KeyRef.of(raw, kid);
} finally {
    Arrays.fill(raw, (byte) 0);   // 金鑰 bytes 用完就覆寫成 0
}
```

不是防記憶體洩漏，是避免金鑰在 GC 回收前還留在 heap 上。

延伸閱讀：[用完就清零：Java 處理金鑰 bytes 的一個小習慣](https://medium.com/@chenboheng3/%E7%94%A8%E5%AE%8C%E5%B0%B1%E6%B8%85%E9%9B%B6-java-%E8%99%95%E7%90%86%E9%87%91%E9%91%B0-bytes-%E7%9A%84%E4%B8%80%E5%80%8B%E5%B0%8F%E7%BF%92%E6%85%A3-f6c2cf47118e)


## 開發環境

- Java 25 (LTS)、Maven 3.10、JUnit 6