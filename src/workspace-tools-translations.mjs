export const workspaceToolsEnglish = {
  '搜索运行记录': 'Search activity',
  '仅显示错误': 'Errors only',
  '没有匹配的运行记录': 'No matching activity',
  '环境已删除，但工作组合记录未能清理。请检查本地存储。': 'The environment was deleted, but its work combinations could not be removed. Check local storage.',
};

const cleanupMessage = '环境已删除，但工作组合记录未能清理。请检查本地存储。';
const cleanupTranslations = {
  'zh-TW': '環境已刪除，但工作組合記錄未能清理。請檢查本機儲存空間。',
  ja: '環境は削除されましたが、作業セットの記録を削除できませんでした。ローカルストレージを確認してください。',
  ko: '환경은 삭제되었지만 작업 조합 기록을 정리하지 못했습니다. 로컬 저장소를 확인하세요.',
  es: 'El entorno se eliminó, pero no sus combinaciones de trabajo. Comprueba el almacenamiento local.',
  fr: 'L’environnement a été supprimé, mais pas ses ensembles de travail. Vérifiez le stockage local.',
  de: 'Die Umgebung wurde gelöscht, ihre Arbeitsgruppen konnten jedoch nicht entfernt werden. Prüfe den lokalen Speicher.',
  'pt-BR': 'O ambiente foi excluído, mas suas combinações de trabalho não puderam ser removidas. Verifique o armazenamento local.',
};
export const workspaceToolsTranslations = {
  'zh-TW': { '搜索运行记录': '搜尋執行記錄', '仅显示错误': '僅顯示錯誤', '没有匹配的运行记录': '沒有相符的執行記錄' },
  ja: { '搜索运行记录': '実行履歴を検索', '仅显示错误': 'エラーのみ', '没有匹配的运行记录': '一致する実行履歴はありません' },
  ko: { '搜索运行记录': '실행 기록 검색', '仅显示错误': '오류만 표시', '没有匹配的运行记录': '일치하는 실행 기록이 없습니다' },
  es: { '搜索运行记录': 'Buscar actividad', '仅显示错误': 'Solo errores', '没有匹配的运行记录': 'No hay actividad coincidente' },
  fr: { '搜索运行记录': 'Rechercher dans l’activité', '仅显示错误': 'Erreurs uniquement', '没有匹配的运行记录': 'Aucune activité correspondante' },
  de: { '搜索运行记录': 'Aktivität durchsuchen', '仅显示错误': 'Nur Fehler', '没有匹配的运行记录': 'Keine passende Aktivität' },
  'pt-BR': { '搜索运行记录': 'Pesquisar atividade', '仅显示错误': 'Somente erros', '没有匹配的运行记录': 'Nenhuma atividade correspondente' },
};
for (const [language, value] of Object.entries(cleanupTranslations)) workspaceToolsTranslations[language][cleanupMessage] = value;
