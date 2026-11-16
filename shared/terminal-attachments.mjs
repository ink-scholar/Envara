export const TERMINAL_ATTACHMENT_LIMITS = Object.freeze({ count: 8, fileBytes: 20 * 1024 * 1024, totalBytes: 50 * 1024 * 1024 });
export const TERMINAL_ATTACHMENT_MESSAGES = Object.freeze({
  TERMINAL_ATTACHMENT_INVALID: '附件无效，请重新选择文件。',
  TERMINAL_ATTACHMENT_LIMIT: '每次最多添加 8 个文件，单个不超过 20 MB，总计不超过 50 MB。',
  TERMINAL_ATTACHMENT_UNSAFE: '附件文件或存储目录不安全，请重新选择。',
  TERMINAL_ATTACHMENT_STORAGE: '无法保存终端附件，请检查空间与权限。',
  TERMINAL_ATTACHMENT_INPUT: '附件已保存，但无法确认路径是否已插入终端。',
  TERMINAL_ATTACHMENT_CANCELLED: '附件传输已取消。',
  TERMINAL_ATTACHMENT_REMOTE: '附件仅支持本地终端；SSH 会话请先将文件传到远端。',
  TERMINAL_ATTACHMENT_UNSUPPORTED: '当前前台程序不支持插入本地附件路径。',
  TERMINAL_ATTACHMENT_BUSY: '正在处理附件，请稍候再输入。',
});
