export const activeStatuses = new Set(['starting', 'running', 'closing']);
/* A tab is a terminal you can use. Ended sessions stay in the snapshot for
 * their output, but they are not offered as if they were still open. */
export const liveSessions = sessions => (sessions ?? []).filter(session => activeStatuses.has(session.status));
export const statusLabels = { starting: '启动中', running: '运行中', closing: '关闭中', exited: '已退出', closed: '已关闭', error: '启动失败' };
