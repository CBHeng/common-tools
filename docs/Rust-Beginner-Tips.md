## 1. Cargo features：依賴的功能開關

**用途**：crate 把非必要功能做成開關，預設關閉；需要時才開，沒開的程式碼和它的依賴都不會被編譯。

**怎麼用**：

```
cargo add aes-gcm --features zeroize    # 開啟指定 feature（簡寫 -F；是 features 複數）
cargo add aes-gcm --no-default-features # 關掉預設 feature，只開自己指定的
```

寫進 `Cargo.toml` 的結果：

```toml
aes-gcm = { version = "0.11.1", features = ["zeroize"] }
```

**注意**：同一個 crate 被多處依賴時，Cargo 會把各處開的 feature 合併，所以你沒開的 feature 也可能被別的依賴打開。

### `#[cfg]` 與 `cfg!()` 的差別

```rust
#[cfg(feature = "log")]      // 屬性：沒開時，這行直接被移除
log::debug!("…");

if cfg!(feature = "log") {   // 巨集：展開成 true / false，等同 if false { … }
    …                        // 這段仍要能通過型別檢查
}
```

| | 會被型別檢查嗎 | 會留在執行檔裡嗎 |
|---|---|---|
| `#[cfg(...)]` 為 false | ❌ | ❌ 一定不會 |
| `cfg!(...)` 為 false | ✅ | release 通常會被最佳化刪掉，debug 可能還在（語言不保證） |

- 分支裡用到**可選依賴**或只在某些情況才存在的 API → 用 `#[cfg]`，`cfg!()` 會編譯失敗。
- 只是依設定決定要不要執行 → 用 `cfg!()`，兩邊都會被檢查，不會出現「關掉時其實編譯不過」。

### 心得

<!-- 待補 -->

參考：[Cargo Features](https://doc.rust-lang.org/cargo/reference/features.html)、[cargo add](https://doc.rust-lang.org/cargo/commands/cargo-add.html)、[std::cfg!](https://doc.rust-lang.org/std/macro.cfg.html)、[Conditional compilation](https://doc.rust-lang.org/reference/conditional-compilation.html)
