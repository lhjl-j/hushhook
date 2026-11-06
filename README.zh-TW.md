# hushhook

hushhook 讓機密和大量輸出不會跑進 AI 程式代理的對話裡。它完全在本機執行、沒有任何相依套件，也不會把資料傳到任何地方。

目前第一個支援的是 Claude Code。核心不綁定特定代理，其他代理之後可以透過小小的轉接層接上來。

*hushhook 是獨立的非官方專案，並非由 Anthropic 製作，也與 Anthropic 沒有關聯或背書關係。*

[English](README.md)

## 為什麼需要它

代理讀的每個檔案、指令印出的每一行，都會變成對話內容，傳給你用的模型服務商。這些工具本來就是這樣運作，大多時候也正是你要的。但只要一次 `cat .env`，或一份囉嗦的 log，就可能把還在用的 API 金鑰一起帶出去，而且送出去就收不回來。

hushhook 擋在代理和工具中間，在常見的狀況抵達模型之前先攔下來：

- **遮蔽工具輸出裡的機密。** 超過 40 種已知格式（AWS、GitHub、GitLab、Slack、Stripe、OpenAI、Anthropic、JWT、私鑰、資料庫網址等）會換成 `[hushhook:<規則 id>]`。
- **擋下敏感檔案的讀取。** `.env`、私鑰、雲端憑證、`.npmrc`、`terraform.tfstate` 等，共 30 種。
- **擋下大量輸出。** 一份 5,000 行的 log 既佔對話空間，又把重點埋起來。代理會收到怎麼縮小範圍的說明。
- **擋下危險指令。** 把下載內容直接交給 shell 執行、刪掉整個家目錄、強制推送、`terraform destroy` 等，共 20 種，每種都有白話的原因。
- **讓代理用更少的內容看懂程式。** `hushhook map` 列出檔案大綱，`hushhook peek` 只看一個函式，讀得少，一樣看得懂。

代理每次都會收到清楚的說明，能自己調整再繼續，不用你出手。

## 30 秒安裝

只需要 Python 3.9 以上，不會再裝其他東西。

**當成 Claude Code 外掛：**

```text
/plugin marketplace add monarchsofchaos004-gif/hushhook
/plugin install hushhook@hushhook
```

**當成命令列工具：**

```bash
pipx install git+https://github.com/monarchsofchaos004-gif/hushhook
hushhook install     # 把 hook 加進 ~/.claude/settings.json，並先備份
hushhook doctor      # 檢查是否一切正常
```

只想用在單一專案，就改跑 `hushhook install --project`。設定裡會寫入你這台機器的路徑，請不要把這個變更存進版本控制。裝好後開一個新的 Claude Code 工作階段。`hushhook uninstall` 只會拿掉它自己加的部分。

## 實際看起來的樣子

代理想讀環境變數檔：

```text
$ cat .env
hushhook blocked reading .env (rule dotenv): this file usually holds secrets.
Ask the user for the specific value you need.
```

指令印出了不該印的東西：

```text
$ env | grep -E 'TOKEN|DATABASE'
GITHUB_TOKEN=[hushhook:github-classic-token]
DATABASE_URL=postgres://app:[hushhook:database-url-password]@db.example.com/app
```

代理想看一份超大的 log：

```text
$ cat build.log
hushhook stopped a big dump: build.log has more than 300 lines. Narrow it first:
read a range, search with grep, or run `hushhook map build.log` for an outline
of a Python or shell file.
```

代理想做無法復原的事：

```text
$ git push --force origin main
hushhook blocked this command (rule git-force-push): a force push can overwrite
other people's commits. Use --force-with-lease, or ask the user. If it is really
intended, ask the user to run it.
```

如果任何工具的輸出還是出現了機密，你會收到提醒，模型則會拿到遮蔽過的版本。`hushhook leaks` 可以看紀錄：時間、工具、規則和次數，紀錄裡絕對不會有機密本身。

## 運作方式

```text
代理準備使用工具
  |
  |-- 執行前：檢查檔案規則、指令規則和大小限制，不通過就擋下並說明原因
  |
  |-- 執行中：Bash 的輸出逐行經過遮蔽
  |
  '-- 執行後：掃描每個工具的輸出，提醒你、給模型遮蔽過的版本，並記一筆紀錄
```

### 你的權限設定維持原樣

hushhook 不會替你核准任何事。Claude Code 是拿 hook 回傳的指令去比對權限規則，所以如果在會詢問的模式下改寫指令，你原本允許清單裡的指令每次都會跳出來問。因此預設的 `"wrap_bash": "auto"` 是這樣運作：

- 關閉權限檢查時（bypass 模式）：改寫 Bash 指令，輸出一邊產生一邊經過遮蔽。
- 其他模式：指令照原樣執行，工具一結束就遮蔽輸出。

不論哪種，模型拿到的都是遮蔽過的內容。想在所有模式都改寫，就設 `"wrap_bash": "always"`；想完全靠執行後那一步，就設 `"never"`。

## 擋不到什麼

hushhook 的目的是減少意外，不是提供保證，它的極限值得先了解。

- **只認得規則裡的格式。** 一般的密碼，或沒有明顯特徵的內部權杖，看起來就跟普通文字一樣。
- **只看得懂常見的 shell 指令。** 腳本開檔後印出來、`python -c`，或先複製檔案再讀，都能繞過檔案規則。不過輸出裡的已知格式還是會被遮蔽。
- **它是安全帶，不是沙盒。** 代理還是能執行程式、連網路、改檔案。代理真的要繞過規則是做得到的。如果你擔心的是這個，請用真正的沙盒。
- **指令規則比對的是文字。** 能抓到危險指令的常見寫法，但不是每一種寫法。
- **只看得到工具呼叫。** 你自己貼進對話的內容，或代理自己寫出來的內容，都會直接過去。 Claude Code 自己加進對話的文字也一樣，例如檔案在磁碟上被改動時的提醒。
- **遮蔽發生在指令跑完之後。** 機密還是被用到了。如果 hushhook 提醒你的是真的機密，請換掉它。
- **替換輸出需要較新版的 Claude Code。** 版本不支援時，你還是會收到提醒和紀錄，但原始輸出會送到模型。Bash 在 bypass 模式下例外，因為遮蔽是在指令裡進行的。
- **hushhook 出錯時，代理會照常運作。** hook 發生任何錯誤，那次呼叫就沒有保護，這是刻意的設計，避免它的問題卡住你的工作。覺得不對勁就跑 `hushhook doctor`。
- **改寫 Bash 指令的兩個副作用。** 只有指令開頭的 `cd` 會延續到下一個指令。如果指令留下仍接著輸出的背景程式，就會等到那支程式結束，這類輸出請導向檔案。結尾是 `&`，或用了 `nohup`、`setsid` 的指令不會被改寫，仍由執行後那一步處理。

支援 Linux 和 macOS，Windows 目前還沒測試過。

## 設定

所有設定都是選用的，放在 `~/.config/hushhook/config.json`：

```json
{
  "max_read_lines": 300,
  "disabled": ["jwt"],
  "extra_rule_dirs": ["~/my-hushhook-rules"],
  "wrap_bash": "auto"
}
```

| 設定 | 作用 | 預設值 |
| --- | --- | --- |
| `max_read_lines` | 超過這個行數的檔案，要讀或要印都得指定範圍或過濾 | `300` |
| `disabled` | 要關閉的規則 id，`hushhook rules` 可以列出全部 | 無 |
| `extra_rule_dirs` | 你自己的規則資料夾，結構是 `<資料夾>/<種類>/<名稱>.rules` | 無 |
| `wrap_bash` | `auto`、`always` 或 `never`，說明見上方 | `auto` |

## 用更少的內容讀程式

支援 Python 和 shell。`map` 不會顯示函式內容；`peek` 會拿掉註解、字串只顯示 `"..."`，要看再另外指定。

```text
$ hushhook map hushhook/hook.py
hushhook/hook.py  44 lines
imports: sys
def L9-23 respond(argv, raw)
def L26-40 main(argv)  -> respond

$ hushhook peek hushhook/hook.py main      # 看一個函式，或指定範圍如 10:40
$ hushhook refs . respond                  # 名稱用在哪裡，不顯示該行內容
$ hushhook doc hushhook/hook.py            # 只看說明文字
```

## 新增規則

一則規則就是文字檔裡的一小段，不用處理 YAML 或 JSON：

```text
id: github-classic-token
pattern: \bghp_[A-Za-z0-9]{36}\b
matches: ghp_{a*36}
ignores: ghp_short
```

如果缺了某種權杖格式、檔案或指令，大約五分鐘就能加上去，而且每個使用 hushhook 的人都會因此受到保護。[CONTRIBUTING.md](CONTRIBUTING.md) 有一步一步的說明。

被誤擋了？`hushhook explain <規則 id>` 會顯示該規則、怎麼關掉，以及回報誤判的連結。要為自己的服務加規則，`hushhook rules new secrets acme-token` 會建好範本並確保設定會載入它，`hushhook rules share acme-token` 會檢查範例並印出連結，讓同樣用這個服務的人也能用上這則規則。

## 授權

[MIT](LICENSE)
