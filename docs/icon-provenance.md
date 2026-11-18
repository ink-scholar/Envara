# 图标来源

[`build/icon.png`](../build/icon.png) 是 Envara 的蓝白双框图标，中央加入一次莫比乌斯带风格的翻面。文件为 1024 × 1024 RGBA PNG，圆角图标外部保留透明背景。

该版本以项目原有蓝白双框图案为基础，使用 OpenAI 图像生成工具制作，再等比例缩小为打包尺寸。打包图校正了透明通道，使蓝色底面完全不透明、圆角外部透明，并保留抗锯齿过渡。图案和 RGB 颜色沿用选定的设计。

[`public/assets/envara-icon.png`](../public/assets/envara-icon.png) 与打包图标内容相同，用于侧栏及首次设置界面。macOS 打包图标和运行时 Dock 图标均使用 `build/icon.png`；README 及各语言介绍也引用该文件。
