// Only the desktop's inspected adapter result can enable an attachment. A
// name, bundle suffix or previously saved binding is not capability evidence.
export const supportsAttachedApplication = (application, platform = 'darwin') =>
  platform !== 'darwin' || application?.compatibility?.supported === true && application.compatibility.adapter === 'chromium-front';

export const canDeleteApplicationData = item =>
  item?.dataScope === 'environment' && item.hasDataDirectory === true && item.running !== true;
