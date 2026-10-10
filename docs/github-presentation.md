# GitHub 展示方案

本文件记录准备好的仓库呈现和设置建议。**2026-10-10 用户已授权上传当前源码进展；0.5.0 仍为开发候选，Notion 启动与清理未验收，尚无公开正式下载，自动发行保持禁用。**

## 首页与语言

- `README.md` 使用中文主文和英文副标，既有品牌图标、简洁徽章与真实界面截图。
- `docs/readme/` 提供繁体中文、英语、日语、韩语、西班牙语、法语、德语与巴西葡萄牙语的完整介绍，九种语言相互导航。
- 各语言统一说明：环境、网络出口、多浏览器、真实终端、附加软件状态、首次语言选择、安装状态、开发、支持与独立许可。
- 不使用“已发布”“全平台支持”“全部验收通过”等无证据徽章。徽章只说明原创代码 MIT、本地 0.5.0 候选与九份 README。
- 当前截图来自隔离夹具的原生 Electron：中文工作区和英文首次启动。网络为合成数据，不是实际出口或附加软件分流证据；另保留历史原生截图链接。
- 深度技术记录继续链接现有能力矩阵、架构、工作区与验证文档，不把历史验证计数堆在首页。

## About 建议

名称保持 **Envara**，中文名 **境舱**。仓库拥有者与应用归属保持现有的 `ink-scholar`；不添加外来作者名或虚构机构。

建议描述：

> Envara · 境舱 — a local desktop workspace for browser profiles, terminals and scoped network contexts.

建议 Topics：`envara`、`electron`、`react`、`browser-profiles`、`local-first`、`terminal`、`workspace`、`anytls`、`privacy`。

网站字段暂不填写未经部署验证的地址。公开下载入口应等 macOS 安装包完成实机验收、资源与许可检查后再添加；目前 0.5.0 尚无公开正式下载。

## Social preview

沿用 `build/icon.png`、暗色背景、Envara / 境舱名称和一句副标，配合真实界面裁图。建议制作 **1280 × 640**、小于 **1 MB** 的 PNG；这是 GitHub 官方推荐规格。当前这里只记录设计和尺寸，尚未上传远程 Social preview。[官方规格](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/customizing-your-repositorys-social-media-preview)

若使用截图，保持清晰字体和单一重点，不露出个人账号、代理密码、订阅 URL、真实 IP 或私密目录。避免把预览截图渲染为已验收的受保护软件。

## 社区入口

新增中英双语 bug / feature Issues 表单和简短 PR 模板，帮助报告系统、版本、实际行为与验证范围。表单不索取密钥、代理密码、Cookie 或完整个人配置。

首页的支持入口指向 [SUPPORT.md](SUPPORT.md)。真实收款渠道未确认前，不创建有效 `.github/FUNDING.yml`，不虚构 Sponsors、Ko-fi 或其他收款主页。

确认公开渠道后，可按需创建：

```yaml
# Only include a channel the maintainer has confirmed and can receive funds through.
# github: confirmed-sponsors-account
# ko_fi: confirmed-public-handle
# custom: ["https://example.org/confirmed-support-page"]
```

上面全部是注释示例，不是项目收款配置。GitHub 支持外部平台和最多四个自定义 URL；Sponsor 按钮与 Sponsors 收款资格是两项不同设置。[Sponsor 按钮说明](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/displaying-a-sponsor-button-in-your-repository) · [Sponsors 收款资格](https://docs.github.com/en/sponsors/getting-started-with-github-sponsors/about-github-sponsors)

## 上传 GitHub 前

macOS 功能实现与实机验收完成后，检查所有语言的功能状态、首启行为与截图一致，核对打包资源和许可，验证目标平台安装、启动与退出，最后更新远程 About、Topics、Social preview、默认分支文档及已确认的支持入口。源码与资源检查通过不等于应用完成；自动发行保持禁用。未经真实平台验收，不把附加软件接管或 Windows 候选改为“可用”。
