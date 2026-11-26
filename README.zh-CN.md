# GeminiRDC

[English](README.md) · [安全模型](SECURITY.md)

GeminiRDC 是一个自托管 MCP 服务，可让 Gemini Apps 查询您 Windows 电脑的硬件、进程和指定工作区。改写或移动文件、建目录、运行 PowerShell 和截图都要在 Windows 上逐次确认。

**当前为预览版。** Gemini 普通聊天已验证硬件查询。开发者模式已验证读文件和提交 PowerShell 请求。MCP 测试覆盖文件写入、命令输出和拒绝截图。普通聊天能发现扩展版工具，实测读文件时 Gemini 未向服务器发出调用。请从开发者模式开始。Gemini 实屏截图回传仍待验收。

## 安装和连接

1. 在 Windows 安装 Python 3.10 或更新版本。克隆仓库后，在 PowerShell 进入项目目录。

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe verify.py
   ```

2. 使用自己的 HTTPS 地址启动服务。默认工作区是项目下的 `workspace\`。也可用 `-Workspace` 指向已有目录。

   ```powershell
   .\start-workspace.ps1 -Origin 'https://bridge.example.com'
   ```

3. 按 [HTTPS 路由说明](README.md#2-start-the-bridge-and-configure-https) 配置反向代理或 Tailscale Funnel。MCP 端口是 `18772`，本机确认页端口 `18773` 留在电脑本地。
4. 在另一个 PowerShell 内运行 `.\pair-workspace.ps1 -Open`。打开 [Gemini 开发者模式](https://gemini.google.com/devmode)，新建应用，填入自己域名下的 `/gemini-pc/mcp`。
5. 跟随 Google 授权流程。在桥接网页看到配对编号后，于本机运行 `.\pair-workspace.ps1 -Approve '<配对编号>'`，再回到浏览器点 **Finish linking**。在 Gemini 保存 **GeminiRDC**，然后用 `.\pair-workspace.ps1 -Close` 关闭新配对窗口。
6. 请 Gemini 用 `get_windows_hardware` 查询配置，或读取您放在工作区的 `hello.txt`。涉及操作时，到 [本机确认页](http://127.0.0.1:18773/review) 核对请求，批准后可在该页查看输出。

Gemini 自定义应用的可用性取决于账号、地区、语言及活动记录设置。[Google 官方说明](https://support.google.com/gemini/answer/17209137)

代码以 [MIT 许可证](LICENSE) 发布。
