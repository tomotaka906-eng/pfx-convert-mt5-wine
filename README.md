# PfxConvert — PFX 変換ツール（MT5 / Wine 用）

**日本語** | [English](README.en.md)

Linux（Ubuntu など）上の Wine で MT5 を動かすとき、ブローカーから受け取った SSL 証明書（`.pfx`）を読み込めずログインできないことがあります。
このツールは、PFX を **Wine 上の MT5 でログインできた形式** に変換する Windows 用の小さなアプリです。

- 秘密鍵: 3DES（pbeWithSHAAnd3-KeyTripleDES-CBC）
- 証明書: 暗号化なし
- MAC: HMAC-SHA1（反復 2048 回）

OpenSSL などの外部ツールは不要で、`PfxConvert.exe` 1 ファイルだけで動きます。画面は日本語と英語に対応しています。

## ダウンロード

[Releases](../../releases/latest) から最新の ZIP（`PfxConvert_v1.1.0.zip`）を入手してください。EXE と説明書（日本語・英語）が入っています。
Release のページに ZIP の SHA-256 を載せているので、必要なら照合してください。

```
certutil -hashfile PfxConvert_v1.1.0.zip SHA256
```

## 使い方

1. `PfxConvert.exe` を起動します。
2. PFX ファイルを点線の枠にドラッグ＆ドロップします（EXE のアイコンにドロップしても、枠をクリックして選んでも構いません）。
3. パスワード入力画面で元のパスワードを入力して「変換する」を押します。パスワードを変えたいときは「新しいパスワードを設定する」にチェックを入れます。
4. 元のファイルと同じ場所に `PFX変換済み` フォルダ（英語表示では `PFX_converted`）が作られ、`元の名前_3DES-SHA1-certNONE.pfx` が保存されて、フォルダが開きます。
5. 変換したファイルを MT5 の証明書フォルダに置きます（次の節）。

詳しくは [説明書.txt](説明書.txt) を参照してください。

## MT5 での証明書の置き場所

MetaQuotes の公式ヘルプでは、証明書ファイル（`*.pfx`）は MT5 の **データフォルダ**の中の `Config\certificates` に置きます。変換したファイルをそこにコピーしてください。

**Windows 版 MT5**: メニュー「ファイル」→「データフォルダを開く」で開いたフォルダの中の `Config\certificates` です。通常のインストールでは、次のような場所です。

```
C:\Users\<ユーザー名>\AppData\Roaming\MetaQuotes\Terminal\<英数字の長い名前>\Config\certificates
```

`/portable` オプションで起動している場合は、MT5 のインストールフォルダ内の `Config\certificates` です。

**Linux（Wine）版 MT5**: MetaQuotes 公式のインストールスクリプト（`mt5linux.sh`）を使うと、Wine の領域は `~/.mt5` に作られます。公式ヘルプが示す MT5 の既定の場所は `~/.mt5/drive_c/Program Files/MetaTrader 5` ですが、Windows 版と同じように Wine のユーザーフォルダの下（`~/.mt5/drive_c/users/<ユーザー名>/AppData/Roaming/MetaQuotes/Terminal/<英数字の長い名前>`）がデータフォルダになる場合もあります。場所が分からないときは、次のコマンドで探せます。

```
find ~/.mt5 ~/.wine -type d -ipath '*/config/certificates' 2>/dev/null
```

何も見つからないときは、MT5 の `Config` フォルダの中に `certificates` フォルダを作ってコピーしてください。

置いたあとの注意:

- 変換前の元のファイルは、`certificates` フォルダに残さず別の場所に保管してください。残っていると、MT5 のログに `loading of standard SSL certificate from PFX failed` と出ることがあります。
- MT5 を再起動してログインを試し、パスワードを求められたら、変換のときに設定したパスワードを入力します。
- MetaQuotes の公式ヘルプでは、証明書のパスワードは 5 文字以上で、英小文字・大文字・数字のうち 2 種類以上を含むこととされています。新しいパスワードを設定するときは、これに合わせると無難です。

参考（MetaQuotes 公式ヘルプ）: [拡張認証](https://www.metatrader5.com/ja/terminal/help/start_advanced/extended_authorization) / [ファイルとフォルダ](https://www.metatrader5.com/ja/terminal/help/start_advanced/structure) / [Linux への MT5 のインストール](https://www.metatrader5.com/en/terminal/help/start_advanced/install_linux)

## 安全性

- ネットワーク通信は一切行いません（ソースに通信用の API は使われていません）。
- 読み書きするのは、指定した PFX と、保存先の `PFX変換済み`（英語表示では `PFX_converted`）フォルダだけです。元のファイルは変更しません。
- 設定ファイルやログファイルは作りません。
- 変換後は、新しいパスワードで読み直して内容が一致することを自動で確認します。

署名のない EXE なので、初回起動時に「Windows によって PC が保護されました」と出ることがあります。気になる場合は、ソースを読んだうえで自分でビルドしてください。

## ビルド

Windows に標準で入っている .NET Framework 4.x の `csc.exe` だけでビルドできます（追加のインストールは不要）。

```
build.bat
```

`PfxConvert.cs`（C# 5 の文法）から `PfxConvert.exe` が作られます。アイコンは `app.ico` です。

## 対応している元ファイル

- 暗号: RC2-40 / RC2-128 / 3DES / AES-128・192・256（PBES2）
- MAC: SHA1 / SHA256 / SHA384 / SHA512 / なし
- Java などで作られた BER 形式（不定長）のファイル
- 鍵は RSA のみ（Wine 10 が RSA 鍵の PFX しか読み込めないため）

## 動作確認と制限

- 外為ファイネスト（FXTF）の MT5 / Ubuntu / Wine 10.0 で、この形式（秘密鍵 3DES・証明書は暗号化なし・MAC SHA1）のファイルでログインできることを確認しています。
- 他のブローカーや Wine のバージョンでは確認していません。
- 元のファイルでログインできなかった原因は特定していません。確認できているのは、「証明書部分を暗号化しない形式」ならログインできたという結果です。
- 新しいパスワードは半角英数字と記号だけにしてください（Wine はパスワードを ASCII として扱います）。
- 画面は日本語と英語に対応しています。OS の表示言語で自動的に選ばれ、画面右上のリンクで切り替えられます（選んだ言語は保存しません）。

## ライセンス

[MIT License](LICENSE)。自由に使用・改変・再配布できます。無保証です。元の PFX ファイルは必ず保管してください。
