import { isInterfaceLanguage } from '../shared/interface-languages.mjs';

/** Closing the last window keeps Envara running for its terminals and
 * attached applications. On macOS the Dock still shows it; Windows and Linux
 * have no such affordance, so the last close there asks before ending that
 * work, and a confirmed close quits through the owned shutdown path. */

const ACTIVE_TERMINAL = new Set(['starting', 'running', 'closing']);
const ACTIVE_APPLICATION = new Set(['starting', 'running', 'stopping']);

export function backgroundWork({ terminals, applications } = {}) {
  const terminalCount = (terminals?.profiles ?? []).reduce((count, profile) =>
    count + (profile.sessions ?? []).filter(session => ACTIVE_TERMINAL.has(session.status)).length, 0);
  const applicationCount = (applications?.applications ?? []).filter(item => ACTIVE_APPLICATION.has(item.status)).length;
  return { terminals: terminalCount, applications: applicationCount, any: terminalCount + applicationCount > 0 };
}

/** Whether a last-window close must be held while background work is checked. */
export function holdsLastWindowClose({ platform = process.platform, remainingViews, quitting, confirmed }) {
  return platform !== 'darwin' && remainingViews === 1 && !quitting && !confirmed;
}

const TEXT = {
  'zh-CN': { title: '仍有任务在运行', message: count => `仍有 ${count} 个终端或附加软件在运行。`, detail: '关闭最后一个窗口会结束它们并退出境舱。', quit: '结束并退出', cancel: '取消' },
  'zh-TW': { title: '仍有工作在執行', message: count => `仍有 ${count} 個終端或附加軟體在執行。`, detail: '關閉最後一個視窗會結束它們並結束境艙。', quit: '結束並退出', cancel: '取消' },
  en: { title: 'Work is still running', message: count => `${count} terminal or attached app session${count === 1 ? ' is' : 's are'} still running.`, detail: 'Closing the last window ends them and quits Envara.', quit: 'End and Quit', cancel: 'Cancel' },
  ja: { title: '実行中の作業があります', message: count => `${count} 個のターミナルまたは連携アプリが実行中です。`, detail: '最後のウィンドウを閉じると、それらを終了して Envara を終了します。', quit: '終了して閉じる', cancel: 'キャンセル' },
  ko: { title: '실행 중인 작업이 있습니다', message: count => `터미널 또는 연결된 앱 ${count}개가 실행 중입니다.`, detail: '마지막 창을 닫으면 이를 종료하고 Envara를 종료합니다.', quit: '종료하고 닫기', cancel: '취소' },
  es: { title: 'Hay trabajo en curso', message: count => `${count} ${count === 1 ? 'terminal o aplicación adjunta sigue' : 'terminales o aplicaciones adjuntas siguen'} en ejecución.`, detail: 'Al cerrar la última ventana se terminarán y Envara se cerrará.', quit: 'Terminar y salir', cancel: 'Cancelar' },
  fr: { title: 'Des tâches sont en cours', message: count => `${count} ${count === 1 ? 'terminal ou application associée est' : 'terminaux ou applications associées sont'} encore en cours d’exécution.`, detail: 'Fermer la dernière fenêtre les arrête et quitte Envara.', quit: 'Arrêter et quitter', cancel: 'Annuler' },
  de: { title: 'Es läuft noch etwas', message: count => `${count} ${count === 1 ? 'Terminal oder angehängte App läuft' : 'Terminals oder angehängte Apps laufen'} noch.`, detail: 'Wenn Sie das letzte Fenster schließen, werden sie beendet und Envara wird geschlossen.', quit: 'Beenden', cancel: 'Abbrechen' },
  'pt-BR': { title: 'Há tarefas em execução', message: count => `${count} ${count === 1 ? 'terminal ou aplicativo anexado ainda está' : 'terminais ou aplicativos anexados ainda estão'} em execução.`, detail: 'Fechar a última janela encerra essas tarefas e sai do Envara.', quit: 'Encerrar e sair', cancel: 'Cancelar' },
};

/** Options for dialog.showMessageBox; button 0 ends the work and quits. */
export function lastWindowCloseDialog(language, work) {
  const text = TEXT[isInterfaceLanguage(language) ? language : 'en'];
  return { type: 'warning', title: text.title, message: text.message(work.terminals + work.applications), detail: text.detail,
    buttons: [text.quit, text.cancel], defaultId: 1, cancelId: 1, noLink: true };
}

export const lastWindowCloseLanguages = Object.freeze(Object.keys(TEXT));
