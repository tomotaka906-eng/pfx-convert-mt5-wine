# PfxConvert — PFX converter for MT5 on Wine

[日本語](README.md) | **English**

When you run MetaTrader 5 on Linux (Ubuntu, etc.) under Wine, the SSL client certificate (`.pfx`) issued by your broker may fail to load and you cannot log in.
PfxConvert is a small Windows app that converts a PFX file into **a format that worked for MT5 login under Wine**:

- Private key: 3DES (pbeWithSHAAnd3-KeyTripleDES-CBC)
- Certificate: not encrypted
- MAC: HMAC-SHA1 (2048 iterations)

No OpenSSL or any other tool is needed. `PfxConvert.exe` is a single file.

> **Note:** the app window is in Japanese only. A label-by-label translation is in [Manual_EN.txt](Manual_EN.txt).

## Download

Get the latest ZIP (`PfxConvert_v1.0.1.zip`) from [Releases](../../releases/latest). It contains the EXE and the manuals (Japanese and English).
The SHA-256 of the ZIP is listed on the release page, so you can verify it:

```
certutil -hashfile PfxConvert_v1.0.1.zip SHA256
```

## How to use

1. Start `PfxConvert.exe`.
2. Drag and drop your PFX file onto the dotted frame (dropping it onto the EXE icon, or clicking the frame to choose the file, also works).
3. In the password dialog, enter the original password and click **変換する** (Convert). To change the password, tick **新しいパスワードを設定する** (Set a new password).
4. A folder named `PFX変換済み` ("PFX converted") is created next to the original file, `<original name>_3DES-SHA1-certNONE.pfx` is saved in it, and the folder opens.
5. Put the converted file into the MT5 certificate folder (next section).

## Where to put the file in MT5

According to the MetaQuotes help, certificate files (`*.pfx`) go into `Config\certificates` inside the MT5 **data folder**. Copy the converted file there.

**MT5 on Windows**: open the data folder with *File → Open Data Folder*, then go to `Config\certificates`. For a normal installation this is typically:

```
C:\Users\<user>\AppData\Roaming\MetaQuotes\Terminal\<long hex name>\Config\certificates
```

If MT5 is started with the `/portable` option, it is `Config\certificates` inside the MT5 installation folder.

**MT5 on Linux (Wine)**: with the official MetaQuotes install script (`mt5linux.sh`), the Wine prefix is created in `~/.mt5`. The MetaQuotes help gives `~/.mt5/drive_c/Program Files/MetaTrader 5` as the default location, but, as on Windows, the data folder may instead be under the Wine user profile (`~/.mt5/drive_c/users/<user>/AppData/Roaming/MetaQuotes/Terminal/<long hex name>`). If you are not sure, find it with:

```
find ~/.mt5 ~/.wine -type d -ipath '*/config/certificates' 2>/dev/null
```

If nothing is found, create a `certificates` folder inside the MT5 `Config` folder and copy the file there.

After copying:

- Do not leave the **original** (unconverted) PFX in the `certificates` folder; keep it somewhere else. If it stays there, the MT5 log may show `loading of standard SSL certificate from PFX failed`.
- Restart MT5 and try to log in. If MT5 asks for the certificate password, enter the one you set during conversion.
- The MetaQuotes help says a certificate password must be at least 5 characters and contain at least two kinds of characters among lower case, upper case and digits. Following this when you set a new password is a safe choice.

References (MetaQuotes help): [Extended authentication](https://www.metatrader5.com/en/terminal/help/start_advanced/extended_authorization) / [Files and folders](https://www.metatrader5.com/en/terminal/help/start_advanced/structure) / [Installing MT5 on Linux](https://www.metatrader5.com/en/terminal/help/start_advanced/install_linux)

## Safety

- The app makes no network connections (the source uses no networking APIs).
- It only reads the PFX you choose and writes to the `PFX変換済み` output folder. The original file is never modified.
- It creates no settings or log files.
- After conversion it re-reads the new file with the new password and checks that the contents match.

The EXE is not code-signed, so Windows SmartScreen may warn you the first time. If you prefer not to run an unsigned EXE, read the source and build it yourself.

## Build

The only requirement is the `csc.exe` that ships with .NET Framework 4.x on Windows (nothing to install):

```
build.bat
```

This builds `PfxConvert.exe` from `PfxConvert.cs` (C# 5 syntax). The icon is `app.ico`.

## Supported input files

- Encryption: RC2-40 / RC2-128 / 3DES / AES-128, 192, 256 (PBES2)
- MAC: SHA1 / SHA256 / SHA384 / SHA512 / none
- BER-encoded (indefinite-length) files, for example those made by Java
- RSA keys only (Wine 10 can import only RSA keys from a PFX)

## Tested environment and limits

- Login worked with a file in this format (3DES private key, unencrypted certificate, MAC SHA1) on the MT5 of Gaitame Finest (FXTF), Ubuntu, Wine 10.0.
- Other brokers and other Wine versions have not been tested.
- The exact reason the original file failed to log in has not been identified. What is confirmed is that the format with an unencrypted certificate part worked.
- Use only ASCII characters in a new password (Wine treats passwords as ASCII).
- The app window is Japanese only; see [Manual_EN.txt](Manual_EN.txt) for translations of the labels and messages.

## License

[MIT License](LICENSE). Free to use, modify and redistribute. No warranty. Always keep your original PFX file.
