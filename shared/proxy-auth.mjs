export const HTTP_PROXY_USERNAME_ERROR_CODE = 'HTTP_PROXY_USERNAME_COLON';
export const HTTP_PROXY_USERNAME_ERROR = 'HTTP/HTTPS 代理用户名不能包含冒号（:）；密码可以包含冒号。';

/** Basic auth separates the username from the password at the first colon. */
export function httpProxyUsernameError(protocol, username) {
  return (protocol === 'http' || protocol === 'https') && typeof username === 'string' && username.includes(':')
    ? HTTP_PROXY_USERNAME_ERROR : '';
}

/** Call at save/use boundaries; stored values must remain readable for repair. */
export function assertHttpProxyUsername(protocol, username) {
  const message = httpProxyUsernameError(protocol, username);
  if (message) throw Object.assign(new Error(message), { code: HTTP_PROXY_USERNAME_ERROR_CODE });
}
